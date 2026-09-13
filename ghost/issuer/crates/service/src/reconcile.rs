//! Reconciliation counters and invariants (Phase 8 design §6.9, §19.3, §19.8; THREAT_MODEL S2,
//! spec C-06). Counters are aggregates without identifiers, updated in the write transaction of
//! the event (and by journal replay exactly as the handler would), kept 400 days.
//!
//! Each counter is keyed by `index u64 || counter id u8`; what the index is depends on the counter
//! ([`IndexKind`]). [`check`] evaluates the invariants that the issuer database alone can prove;
//! [`check_relays`] adds the per-week redemption counts the relay operators report, and
//! [`check_view`] the payout workstation's independent view wallet (`ghost-issuer-ops
//! reconcile-check`, §6.9 "independent checks").
//!
//! **Retention.** A counter is deleted when the week its retention runs from is 58 weeks (≥ 400
//! days) old. That week is its index's first week, except for the counters of a credit epoch c,
//! whose credits are presented until the start of epoch c + 5 (§19.8): they run from then, so a
//! credit epoch's counters never vanish while its credits are still redeemed (the S4 anchor at the
//! epoch's first week dropped them in the last weeks of the acceptance window).
//!
//! **Totals** (recorded addition to §6.9). Every addition to `xmr_credited_atomic`,
//! `payout_queued_atomic` and `payout_paid_atomic` also adds, in the same transaction, to a total
//! counter that is never swept: the credited revenue since the first start (the payout batch
//! file's `cumulative_credited_atomic`, which the workstation compares with what its own view
//! wallet received) and the payouts queued and paid, compared with each other (a claim queued in
//! one week may be paid in a later one, so the per-week counters of the two sides are swept at
//! different times).
//!
//! **Refused payouts** (recorded addition to §6.9, S6 review): `payout_refused_atomic`, per week
//! of the acknowledgement, counts queued payouts the workstation refused (a payout address it had
//! seen before, §9.5 step 2). Their credits stay spent; `payout_paid_atomic` never includes them.

use std::collections::{BTreeMap, BTreeSet};

use ghost_entitlement::grid::{
    credit_epoch, invite_epoch, price_epoch, week, WEEKS_PER_CREDIT_EPOCH, WEEKS_PER_INVITE_EPOCH,
};
use ghost_entitlement::Schedule;

use crate::credit::ACCEPTED_PAST_EPOCHS;
use crate::store::{be_u64, ReadTx, StoreError, Table, WriteTx};

/// Counters are deleted when the week their retention runs from is this many weeks old
/// (58 weeks ≥ 400 d).
pub const RETENTION_WEEKS: u64 = 58;
/// The index of the total counters.
pub const TOTAL_INDEX: u64 = 0;

/// The counters of §6.9 plus the pool reconciliation alarm of §19.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CounterId {
    PacksXmr,
    PacksCredit,
    XmrCreditedAtomic,
    OverpaidAtomic,
    UnattributedAtomic,
    Trials,
    SignedAccess,
    SignedInvite,
    SignedCredit,
    CreditsDiscount,
    CreditsDiscountAtomic,
    CreditsPayout,
    CreditsRefreshed,
    PayoutQueuedAtomic,
    PayoutPaidAtomic,
    ReorgAfterIssue,
    ConfirmedUnissued,
    PoolReconciled,
    /// Σ `xmr_credited_atomic` since the first start (never swept).
    XmrCreditedTotal,
    /// Σ `payout_queued_atomic` since the first start (never swept).
    PayoutQueuedTotal,
    /// Σ `payout_paid_atomic` since the first start (never swept).
    PayoutPaidTotal,
    /// Queued payouts the workstation refused (a payout address it had seen before, §9.5 step 2),
    /// per week of the acknowledgement; their credits stay spent.
    PayoutRefusedAtomic,
}

/// What a counter's index means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndexKind {
    /// The base week of the pack or trial.
    BaseWeek,
    /// The week of the event (`week(now)`).
    EventWeek,
    /// An access week.
    AccessWeek,
    InviteEpoch,
    CreditEpoch,
    PriceEpoch,
    /// [`TOTAL_INDEX`]: a total since the first start.
    Total,
}

impl CounterId {
    pub const ALL: [CounterId; 22] = [
        CounterId::PacksXmr,
        CounterId::PacksCredit,
        CounterId::XmrCreditedAtomic,
        CounterId::OverpaidAtomic,
        CounterId::UnattributedAtomic,
        CounterId::Trials,
        CounterId::SignedAccess,
        CounterId::SignedInvite,
        CounterId::SignedCredit,
        CounterId::CreditsDiscount,
        CounterId::CreditsDiscountAtomic,
        CounterId::CreditsPayout,
        CounterId::CreditsRefreshed,
        CounterId::PayoutQueuedAtomic,
        CounterId::PayoutPaidAtomic,
        CounterId::ReorgAfterIssue,
        CounterId::ConfirmedUnissued,
        CounterId::PoolReconciled,
        CounterId::XmrCreditedTotal,
        CounterId::PayoutQueuedTotal,
        CounterId::PayoutPaidTotal,
        CounterId::PayoutRefusedAtomic,
    ];

    pub fn code(self) -> u8 {
        match self {
            CounterId::PacksXmr => 1,
            CounterId::PacksCredit => 2,
            CounterId::XmrCreditedAtomic => 3,
            CounterId::OverpaidAtomic => 4,
            CounterId::UnattributedAtomic => 5,
            CounterId::Trials => 6,
            CounterId::SignedAccess => 7,
            CounterId::SignedInvite => 8,
            CounterId::SignedCredit => 9,
            CounterId::CreditsDiscount => 10,
            CounterId::CreditsDiscountAtomic => 11,
            CounterId::CreditsPayout => 12,
            CounterId::CreditsRefreshed => 13,
            CounterId::PayoutQueuedAtomic => 14,
            CounterId::PayoutPaidAtomic => 15,
            CounterId::ReorgAfterIssue => 16,
            CounterId::ConfirmedUnissued => 17,
            CounterId::PoolReconciled => 18,
            CounterId::XmrCreditedTotal => 19,
            CounterId::PayoutQueuedTotal => 20,
            CounterId::PayoutPaidTotal => 21,
            CounterId::PayoutRefusedAtomic => 22,
        }
    }

    pub fn from_code(c: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|id| id.code() == c)
    }

    pub fn index_kind(self) -> IndexKind {
        match self {
            CounterId::PacksXmr
            | CounterId::PacksCredit
            | CounterId::XmrCreditedAtomic
            | CounterId::Trials => IndexKind::BaseWeek,
            CounterId::SignedAccess => IndexKind::AccessWeek,
            CounterId::SignedInvite => IndexKind::InviteEpoch,
            CounterId::SignedCredit
            | CounterId::CreditsDiscount
            | CounterId::CreditsPayout
            | CounterId::CreditsRefreshed => IndexKind::CreditEpoch,
            CounterId::CreditsDiscountAtomic => IndexKind::PriceEpoch,
            CounterId::OverpaidAtomic
            | CounterId::UnattributedAtomic
            | CounterId::PayoutQueuedAtomic
            | CounterId::PayoutPaidAtomic
            | CounterId::PayoutRefusedAtomic
            | CounterId::ReorgAfterIssue
            | CounterId::ConfirmedUnissued
            | CounterId::PoolReconciled => IndexKind::EventWeek,
            CounterId::XmrCreditedTotal
            | CounterId::PayoutQueuedTotal
            | CounterId::PayoutPaidTotal => IndexKind::Total,
        }
    }

    /// The week a counter's retention runs from: its index's first week, the start of epoch
    /// c + 5 for a credit epoch c (its credits are presented until then, §19.8), never for a
    /// total.
    pub fn index_week(self, index: u64) -> u64 {
        match self.index_kind() {
            IndexKind::BaseWeek | IndexKind::EventWeek | IndexKind::AccessWeek => index,
            IndexKind::InviteEpoch => index.saturating_mul(WEEKS_PER_INVITE_EPOCH),
            IndexKind::CreditEpoch => index
                .saturating_add(ACCEPTED_PAST_EPOCHS + 1)
                .saturating_mul(WEEKS_PER_CREDIT_EPOCH),
            IndexKind::PriceEpoch => index.saturating_mul(WEEKS_PER_CREDIT_EPOCH),
            IndexKind::Total => u64::MAX,
        }
    }

    /// The total counter an addition to this counter also adds to.
    fn total(self) -> Option<CounterId> {
        match self {
            CounterId::XmrCreditedAtomic => Some(CounterId::XmrCreditedTotal),
            CounterId::PayoutQueuedAtomic => Some(CounterId::PayoutQueuedTotal),
            CounterId::PayoutPaidAtomic => Some(CounterId::PayoutPaidTotal),
            _ => None,
        }
    }
}

fn key(id: CounterId, index: u64) -> [u8; 9] {
    let mut k = [0u8; 9];
    k[..8].copy_from_slice(&index.to_be_bytes());
    k[8] = id.code();
    k
}

pub fn add(tx: &mut dyn WriteTx, id: CounterId, index: u64, delta: u64) -> Result<(), StoreError> {
    if delta == 0 {
        return Ok(());
    }
    if let Some(total) = id.total() {
        bump(tx, total, TOTAL_INDEX, delta)?;
    }
    bump(tx, id, index, delta)
}

fn bump(tx: &mut dyn WriteTx, id: CounterId, index: u64, delta: u64) -> Result<(), StoreError> {
    let k = key(id, index);
    let current = tx
        .get(Table::Counter, &k)?
        .map(|v| be_u64(&v))
        .transpose()?;
    tx.put(
        Table::Counter,
        &k,
        &current.unwrap_or(0).saturating_add(delta).to_be_bytes(),
    )
}

pub fn get(tx: &dyn ReadTx, id: CounterId, index: u64) -> Result<u64, StoreError> {
    Ok(tx
        .get(Table::Counter, &key(id, index))?
        .map(|v| be_u64(&v))
        .transpose()?
        .unwrap_or(0))
}

/// Every counter.
pub type Counters = BTreeMap<(CounterId, u64), u64>;

pub fn all(tx: &dyn ReadTx) -> Result<Counters, StoreError> {
    let mut out = BTreeMap::new();
    for (k, v) in tx.range(Table::Counter, &[], None)? {
        if k.len() != 9 {
            return Err(StoreError::Corrupt);
        }
        let id = CounterId::from_code(k[8]).ok_or(StoreError::Corrupt)?;
        out.insert((id, be_u64(&k[..8])?), be_u64(&v)?);
    }
    Ok(out)
}

/// Deletes every counter whose index week is at least [`RETENTION_WEEKS`] old.
pub fn sweep(tx: &mut dyn WriteTx, now: u64) -> Result<(), StoreError> {
    let limit = week(now).saturating_sub(RETENTION_WEEKS);
    for ((id, index), _) in all(tx)? {
        if id.index_week(index) < limit {
            tx.delete(Table::Counter, &key(id, index))?;
        }
    }
    Ok(())
}

/// A violated invariant of §6.9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mismatch {
    /// `signed[ACCESS][w] != access_per_slot·|slots(w)|·(packs covering w)
    /// + trial_per_slot·|slots(w)|·(trials covering w)`.
    SignedAccess { week: u64 },
    /// `signed[INVITE][e] != invites_per_pack·(packs of invite epoch e)`.
    SignedInvite { epoch: u64 },
    /// `signed[CREDIT][c] != XMR packs of credit epoch c + credits_refreshed[c]`.
    SignedCredit { epoch: u64 },
    /// `credits_discount[c] + credits_payout[c] + credits_refreshed[c] > signed[CREDIT][c]`.
    CreditsExceedSigned { epoch: u64 },
    /// `xmr_credited_atomic[b] < price(price_epoch(b))·packs_xmr[b]`.
    XmrCredited { base_week: u64 },
    /// `credits_discount_atomic > Σ_c credits_discount[c]·price(c)/10`.
    DiscountValue,
    /// `payout_paid > payout_queued` (totals) or `payout_queued > Σ_c
    /// credits_payout[c]·price(c)/10`.
    PayoutValue,
    /// The relays' redemptions of week w over all slots exceed `access_per_slot·|slots(w)|·(packs
    /// covering w) + trial_per_slot·|slots(w)|·(trials covering w)` (§6.9 check 2, §19.3).
    RelayRedemptions { week: u64 },
    /// The workstation's view wallet received less than the issuer claims to have credited.
    ViewBelowCredited,
    /// Cumulative payouts exceed 10 % of the value the workstation's view wallet received.
    PayoutCap,
}

/// The oldest access week whose counters are all still retained at `now`.
fn oldest_checked_week(now: u64) -> u64 {
    week(now).saturating_sub(RETENTION_WEEKS - 6)
}

fn counted(counters: &Counters, id: CounterId, index: u64) -> u64 {
    counters.get(&(id, index)).copied().unwrap_or(0)
}

fn counted_indices(counters: &Counters, id: CounterId) -> BTreeSet<u64> {
    counters
        .keys()
        .filter(|(i, _)| *i == id)
        .map(|(_, index)| *index)
        .collect()
}

/// `access_per_slot·|slots(w)|·(packs covering w) + trial_per_slot·|slots(w)|·(trials covering
/// w)`: the ACCESS tokens of week w the counted packs and trials were signed for.
pub fn expected_access(counters: &Counters, schedule: &Schedule, w: u64) -> u64 {
    let c = schedule.constants();
    let slots = schedule.slots_in_week(w).len() as u64;
    let packs = |b: u64| {
        counted(counters, CounterId::PacksXmr, b).saturating_add(counted(
            counters,
            CounterId::PacksCredit,
            b,
        ))
    };
    let covering_packs: u64 = (w.saturating_sub(4)..=w).map(packs).sum();
    let covering_trials: u64 = (w.saturating_sub(1)..=w)
        .map(|b| counted(counters, CounterId::Trials, b))
        .sum();
    u64::from(c.access_per_slot) * slots * covering_packs
        + u64::from(c.trial_per_slot) * slots * covering_trials
}

/// The invariants of §6.9 the issuer database alone proves. Indices whose contributing counters
/// may already have been deleted by retention are skipped.
pub fn check(counters: &Counters, schedule: &Schedule, now: u64) -> Vec<Mismatch> {
    let c = schedule.constants();
    let get = |id: CounterId, index: u64| counted(counters, id, index);
    let indices = |id: CounterId| counted_indices(counters, id);
    let oldest = oldest_checked_week(now);
    let mut out = Vec::new();

    let mut pack_weeks = indices(CounterId::PacksXmr);
    pack_weeks.extend(indices(CounterId::PacksCredit));
    let trial_weeks = indices(CounterId::Trials);
    let packs = |b: u64| get(CounterId::PacksXmr, b).saturating_add(get(CounterId::PacksCredit, b));

    // Access weeks.
    let mut weeks = indices(CounterId::SignedAccess);
    for &b in &pack_weeks {
        weeks.extend(b..b.saturating_add(5));
    }
    for &b in &trial_weeks {
        weeks.extend(b..b.saturating_add(2));
    }
    for w in weeks.into_iter().filter(|&w| w >= oldest) {
        if get(CounterId::SignedAccess, w) != expected_access(counters, schedule, w) {
            out.push(Mismatch::SignedAccess { week: w });
        }
    }

    // Invite epochs.
    let mut invite_epochs = indices(CounterId::SignedInvite);
    invite_epochs.extend(pack_weeks.iter().map(|&b| invite_epoch(b)));
    for e in invite_epochs
        .into_iter()
        .filter(|&e| e.saturating_mul(WEEKS_PER_INVITE_EPOCH) >= oldest)
    {
        let packs_in: u64 = pack_weeks
            .iter()
            .filter(|&&b| invite_epoch(b) == e)
            .map(|&b| packs(b))
            .sum();
        if get(CounterId::SignedInvite, e) != u64::from(c.invites_per_pack) * packs_in {
            out.push(Mismatch::SignedInvite { epoch: e });
        }
    }

    // Credit epochs.
    let mut credit_epochs = indices(CounterId::SignedCredit);
    for id in [
        CounterId::CreditsDiscount,
        CounterId::CreditsPayout,
        CounterId::CreditsRefreshed,
    ] {
        credit_epochs.extend(indices(id));
    }
    credit_epochs.extend(pack_weeks.iter().map(|&b| credit_epoch(b)));
    for e in credit_epochs
        .into_iter()
        .filter(|&e| e.saturating_mul(WEEKS_PER_CREDIT_EPOCH) >= oldest)
    {
        let xmr_packs: u64 = pack_weeks
            .iter()
            .filter(|&&b| credit_epoch(b) == e)
            .map(|&b| get(CounterId::PacksXmr, b))
            .sum();
        let signed = get(CounterId::SignedCredit, e);
        if signed != xmr_packs + get(CounterId::CreditsRefreshed, e) {
            out.push(Mismatch::SignedCredit { epoch: e });
        }
        let used = get(CounterId::CreditsDiscount, e)
            + get(CounterId::CreditsPayout, e)
            + get(CounterId::CreditsRefreshed, e);
        if used > signed {
            out.push(Mismatch::CreditsExceedSigned { epoch: e });
        }
    }

    // XMR revenue per base week.
    for b in indices(CounterId::PacksXmr)
        .into_iter()
        .filter(|&b| b >= oldest)
    {
        let price = schedule.pack_price(price_epoch(b)).unwrap_or(u64::MAX);
        if get(CounterId::XmrCreditedAtomic, b) < price.saturating_mul(get(CounterId::PacksXmr, b))
        {
            out.push(Mismatch::XmrCredited { base_week: b });
        }
    }

    // Values of redeemed credits (per-epoch prices, §19.8).
    let value_of = |id: CounterId| -> u64 {
        indices(id)
            .into_iter()
            .map(|e| get(id, e).saturating_mul(schedule.credit_value(e).unwrap_or(0)))
            .fold(0u64, u64::saturating_add)
    };
    let total = |id: CounterId| -> u64 {
        indices(id)
            .into_iter()
            .map(|i| get(id, i))
            .fold(0u64, u64::saturating_add)
    };
    if total(CounterId::CreditsDiscountAtomic) > value_of(CounterId::CreditsDiscount) {
        out.push(Mismatch::DiscountValue);
    }
    // The retained per-week queued amounts against the credit-epoch counts, which are retained at
    // least as long (their retention runs from the end of the credits' acceptance); paid against
    // queued on the totals.
    let queued = total(CounterId::PayoutQueuedAtomic);
    if get(CounterId::PayoutPaidTotal, TOTAL_INDEX) > get(CounterId::PayoutQueuedTotal, TOTAL_INDEX)
        || queued > value_of(CounterId::CreditsPayout)
    {
        out.push(Mismatch::PayoutValue);
    }
    out.sort();
    out.dedup();
    out
}

/// §6.9 check 2 (§19.3): `redemptions` maps an access week to the sum over all slots of the
/// redemptions the relay operators reported for it; each must stay within
/// [`expected_access`]. Per-slot counts are a blinded client choice and never an alarm. Weeks whose
/// pack or trial counters may already be swept are skipped.
pub fn check_relays(
    counters: &Counters,
    schedule: &Schedule,
    now: u64,
    redemptions: &BTreeMap<u64, u64>,
) -> Vec<Mismatch> {
    let oldest = oldest_checked_week(now);
    redemptions
        .iter()
        .filter(|(&w, &n)| w >= oldest && n > expected_access(counters, schedule, w))
        .map(|(&week, _)| Mismatch::RelayRedemptions { week })
        .collect()
}

/// §6.9 check 1 (§19.7): the payout workstation's own view wallet received `incoming` (Σ qualifying
/// transfers to minors ≥ 1 since the treasury's restore height). The issuer's cumulative credited
/// revenue must not exceed it, and the cumulative payouts `paid_so_far` (the workstation ledger)
/// must stay within 10 % of it.
pub fn check_view(cumulative_credited: u64, incoming: u64, paid_so_far: u64) -> Vec<Mismatch> {
    let mut out = Vec::new();
    if cumulative_credited > incoming {
        out.push(Mismatch::ViewBelowCredited);
    }
    if !within_cap(paid_so_far, incoming) {
        out.push(Mismatch::PayoutCap);
    }
    out
}

/// The referral cap (MS-4, §19.7): `payouts ≤ 10 % × incoming`, in exact integer arithmetic.
pub fn within_cap(payouts: u64, incoming: u64) -> bool {
    u128::from(payouts) * 10 <= u128::from(incoming)
}
