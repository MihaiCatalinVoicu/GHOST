//! Reconciliation counters and invariants (Phase 8 design §6.9, §19.3, §19.8; THREAT_MODEL S2,
//! spec C-06). Counters are aggregates without identifiers, updated in the write transaction of
//! the event (and by journal replay exactly as the handler would), kept 400 days.
//!
//! Each counter is keyed by `index u64 || counter id u8`; what the index is depends on the counter
//! ([`IndexKind`]). [`check`] evaluates the invariants that the issuer database alone can prove;
//! `ghost-issuer-ops reconcile-check` (slice S6) adds the relay aggregates and the workstation's
//! independent view wallet.

use std::collections::{BTreeMap, BTreeSet};

use ghost_entitlement::grid::{
    credit_epoch, invite_epoch, price_epoch, week, WEEKS_PER_CREDIT_EPOCH, WEEKS_PER_INVITE_EPOCH,
};
use ghost_entitlement::Schedule;

use crate::store::{be_u64, ReadTx, StoreError, Table, WriteTx};

/// Counters are deleted when their index's first week is this many weeks old (58 weeks ≥ 400 d).
pub const RETENTION_WEEKS: u64 = 58;

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
}

impl CounterId {
    pub const ALL: [CounterId; 18] = [
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
            | CounterId::ReorgAfterIssue
            | CounterId::ConfirmedUnissued
            | CounterId::PoolReconciled => IndexKind::EventWeek,
        }
    }

    /// The first access week an index covers (the retention clock).
    pub fn index_week(self, index: u64) -> u64 {
        match self.index_kind() {
            IndexKind::BaseWeek | IndexKind::EventWeek | IndexKind::AccessWeek => index,
            IndexKind::InviteEpoch => index.saturating_mul(WEEKS_PER_INVITE_EPOCH),
            IndexKind::CreditEpoch | IndexKind::PriceEpoch => {
                index.saturating_mul(WEEKS_PER_CREDIT_EPOCH)
            }
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
    /// `payout_paid > payout_queued` or `payout_queued > Σ_c credits_payout[c]·price(c)/10`.
    PayoutValue,
}

/// The invariants of §6.9 the issuer database alone proves. Indices whose contributing counters
/// may already have been deleted by retention are skipped.
pub fn check(counters: &Counters, schedule: &Schedule, now: u64) -> Vec<Mismatch> {
    let c = schedule.constants();
    let get = |id: CounterId, index: u64| counters.get(&(id, index)).copied().unwrap_or(0);
    let indices = |id: CounterId| -> BTreeSet<u64> {
        counters
            .keys()
            .filter(|(i, _)| *i == id)
            .map(|(_, index)| *index)
            .collect()
    };
    let oldest = week(now).saturating_sub(RETENTION_WEEKS - 6);
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
        let slots = schedule.slots_in_week(w).len() as u64;
        let covering_packs: u64 = (w.saturating_sub(4)..=w).map(packs).sum();
        let covering_trials: u64 = (w.saturating_sub(1)..=w)
            .map(|b| get(CounterId::Trials, b))
            .sum();
        let expected = u64::from(c.access_per_slot) * slots * covering_packs
            + u64::from(c.trial_per_slot) * slots * covering_trials;
        if get(CounterId::SignedAccess, w) != expected {
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
    let queued = total(CounterId::PayoutQueuedAtomic);
    if total(CounterId::PayoutPaidAtomic) > queued || queued > value_of(CounterId::CreditsPayout) {
        out.push(Mismatch::PayoutValue);
    }
    out.sort();
    out.dedup();
    out
}
