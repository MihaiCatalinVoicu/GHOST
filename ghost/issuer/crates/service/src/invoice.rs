//! The invoice state machine (Phase 8 design §5.4) and the crediting rule (§7.3, §19.5 rule 4,
//! §19.6), as pure functions over one rail view. The scanner applies them in one write
//! transaction per tick; a tick is idempotent (the same view changes nothing twice).
//!
//! ```text
//!             scanner: seen > 0             scanner: credited >= amount        BlindSign committed
//!   CREATED ─────────────────────► SEEN ─────────────────────────► CONFIRMED ─────────────────► ISSUED
//!      │ (amount 0: created CONFIRMED)  ▲  reorg: credited < amount    │                            │
//!      │                                └──────────────────────────────┘  unissued 30 d: purge      │ +7 d
//!      │ synced ∧ wallet_height ≥ grace_height + C ∧ credited < amount                              ▼
//!      └──────────────────────────────► EXPIRED ──(+7 d)──► purged                               purged
//! ```

use std::collections::BTreeSet;

use ghost_entitlement::batch::PACK_WEEKS;
use ghost_entitlement::grid::{credit_epoch, invite_epoch};
use ghost_entitlement::Kind;

use crate::rail::{IncomingEntry, RailHeight};
use crate::store::{InvoiceRow, InvoiceState, PayWith};

/// Blocks after issuance or expiry before an invoice is purged (≈ 7 days).
pub const PURGE_AFTER_BLOCKS: u64 = 5_040;
/// Blocks after confirmation before a CONFIRMED-unissued invoice is purged (≈ 30 days).
pub const UNISSUED_KEEP_BLOCKS: u64 = 21_600;
/// Transfers mined this many blocks below `created_height` still count (reorg margin, §19.5).
pub const REORG_MARGIN_BLOCKS: u64 = 20;
/// A txid already credited stays timely if re-mined at most this far above `grace_height` (§19.6).
pub const TIMELY_REORG_BLOCKS: u64 = 100;

/// The amounts of one XMR invoice over one rail view.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Amounts {
    /// Qualifying transfers: ≥ C confirmations, `unlock_time` 0, not double-spent, mined at
    /// `height ≥ created − 20` and before grace (or a timely re-mined credited txid).
    pub credited: u64,
    /// Pool transfers and `in` transfers below C confirmations (unlock 0, not double-spent).
    pub seen: u64,
    /// The txids counted in `credited`, with their heights.
    pub credited_txids: Vec<([u8; 32], u64)>,
}

/// True when `t` may count for an invoice at all: its minor, `unlock_time` 0, not double-spent.
fn eligible(row: &InvoiceRow, t: &IncomingEntry) -> bool {
    t.minor == row.minor && row.minor != 0 && t.unlock_time == 0 && !t.double_spend_seen
}

/// The crediting rule of §7.3. `recorded` are the txids already in `credited_tx` for this
/// invoice.
pub fn amounts(
    row: &InvoiceRow,
    transfers: &[IncomingEntry],
    confirmations: u64,
    recorded: &BTreeSet<[u8; 32]>,
) -> Amounts {
    let mut out = Amounts::default();
    let floor = row.created_height.saturating_sub(REORG_MARGIN_BLOCKS);
    for t in transfers.iter().filter(|t| eligible(row, t)) {
        match t.height {
            None => out.seen = out.seen.saturating_add(t.amount_atomic),
            Some(h) if h >= floor => {
                if t.confirmations < confirmations {
                    out.seen = out.seen.saturating_add(t.amount_atomic);
                } else if h <= row.grace_height
                    || (recorded.contains(&t.txid)
                        && h <= row.grace_height.saturating_add(TIMELY_REORG_BLOCKS))
                {
                    out.credited = out.credited.saturating_add(t.amount_atomic);
                    out.credited_txids.push((t.txid, h));
                }
            }
            Some(_) => {}
        }
    }
    out
}

/// True when a qualifying transfer `t` (≥ C confirmations, unlock 0, not double-spent) was counted
/// in the invoice's credit under the rule of [`amounts`].
pub fn credits_invoice(row: &InvoiceRow, t: &IncomingEntry, recorded: &BTreeSet<[u8; 32]>) -> bool {
    let Some(h) = t.height else { return false };
    eligible(row, t)
        && h >= row.created_height.saturating_sub(REORG_MARGIN_BLOCKS)
        && (h <= row.grace_height
            || (recorded.contains(&t.txid)
                && h <= row.grace_height.saturating_add(TIMELY_REORG_BLOCKS)))
}

/// The state after a recomputation of a CREATED, SEEN or CONFIRMED XMR invoice (§5.4 table).
/// Returns the new row fields (state, confirmed_height, purge_height, credited, seen).
pub fn recompute(row: &InvoiceRow, a: &Amounts, h: &RailHeight, confirmations: u64) -> InvoiceRow {
    let mut next = row.clone();
    next.credited = a.credited;
    next.seen = a.seen;
    if a.credited >= row.amount {
        if row.state != InvoiceState::Confirmed {
            next.confirmed_height = h.wallet;
        }
        next.state = InvoiceState::Confirmed;
    } else if h.synced_view() && h.wallet >= row.grace_height.saturating_add(confirmations) {
        // Negative decisions only from a synced view (MM10 ExpireFromStaleView).
        next.state = InvoiceState::Expired;
        next.purge_height = h.wallet.saturating_add(PURGE_AFTER_BLOCKS);
    } else if a.credited.saturating_add(a.seen) > 0 {
        next.state = InvoiceState::Seen;
    } else {
        next.state = InvoiceState::Created;
    }
    next
}

/// True when the invoice is due for purge at wallet height `wallet` (§5.4 purge row). Heights of
/// 0 are not stamped yet and never purge.
pub fn purge_due(row: &InvoiceRow, wallet: u64) -> bool {
    match row.state {
        InvoiceState::Issued => {
            row.issued_height > 0 && wallet >= row.issued_height.saturating_add(PURGE_AFTER_BLOCKS)
        }
        InvoiceState::Expired => wallet >= row.purge_height,
        InvoiceState::Confirmed => {
            row.confirmed_height > 0
                && wallet >= row.confirmed_height.saturating_add(UNISSUED_KEEP_BLOCKS)
        }
        InvoiceState::Created | InvoiceState::Seen => false,
    }
}

/// The state a client is told (`InvoiceState` on the wire) for a stored invoice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reported {
    AwaitingPayment,
    AwaitingConfirmations,
    Underpaid,
    Expired,
    /// CONFIRMED and not yet issued: `BlindSign` signs; `InvoiceStatus` reports
    /// AWAITING_CONFIRMATIONS with `credited_atomic ≥ amount`.
    Confirmed,
    Issued,
}

pub fn reported(row: &InvoiceRow) -> Reported {
    match row.state {
        InvoiceState::Created | InvoiceState::Seen => {
            let total = row.credited.saturating_add(row.seen);
            if total == 0 {
                Reported::AwaitingPayment
            } else if total < row.amount {
                Reported::Underpaid
            } else {
                Reported::AwaitingConfirmations
            }
        }
        InvoiceState::Confirmed => Reported::Confirmed,
        InvoiceState::Issued => Reported::Issued,
        InvoiceState::Expired => Reported::Expired,
    }
}

/// Every (kind, epoch) the pack layout of an invoice references (§4.2): ACCESS weeks
/// base..base+4, the INVITE epoch of base and, when paid in XMR, the CREDIT epoch of base. These
/// private keys stay loaded while the invoice is open (§19.1 rule 1).
pub fn layout_keys(base_week: u64, pay_with: PayWith) -> Vec<(Kind, u64)> {
    let mut keys: Vec<(Kind, u64)> = (0..PACK_WEEKS)
        .map(|i| (Kind::Access, base_week.saturating_add(i)))
        .collect();
    keys.push((Kind::Invite, invite_epoch(base_week)));
    if pay_with == PayWith::Monero {
        keys.push((Kind::Credit, credit_epoch(base_week)));
    }
    keys
}
