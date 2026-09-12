//! The scanner (Phase 8 design §7.3, normative; §19.5 rule 4, §19.6): every tick recomputes every
//! open XMR invoice from one rail view, independently of client calls, and applies the §5.4
//! transitions, the credited-txid record, the purges and the rail counters in one write
//! transaction. Recomputation, not special cases, handles reorgs inside the wallet's window; a
//! tick on the same view changes nothing; EXPIRED is decided only from a synced view.
//!
//! ```text
//! scan_tick_at(now):
//!   h = rail.height()                                   any error: no progress, no state change
//!   from = min(created_height over open XMR invoices) − 20, and scan_final_height + 1
//!   xs = rail.transfers(from, h.wallet)                 one call per tick for the whole account
//!   one write transaction: unattributed revenue over (scan_final_height, h.wallet − C] (synced
//!   views only), every invoice recomputed, stamped or purged, reorg_after_issue counted
//! ```
//!
//! Unattributed revenue (§19.6 rule 2) is decided per transfer when it becomes final; a transfer
//! credited to an invoice that later expires was counted as attributed then, so at the expiry the
//! invoice's credited amount is added to `unattributed_atomic` in the same transaction. With the
//! issuance (`xmr_credited_atomic`) and purge (`overpaid_atomic`) counters every final transfer to a
//! minor ≥ 1 is thus counted once: incoming = credited + overpaid + unattributed.
//!
//! **Complete view** (review finding S5-MON-1). A view-only wallet restored from its keys without
//! runbook R5's replay holds fewer subaddresses than the issuer handed out and misses every
//! payment beyond its lookahead. Every tick therefore compares the wallet's subaddress count with
//! `highest_minor` after the refresh; while `count − 1 < highest_minor` it decides nothing (no
//! state change, no EXPIRED, no unattributed revenue), and the missing synced tick makes new XMR
//! invoices `UNAVAILABLE`; `status.json` reports `WALLET_INCOMPLETE` until the replay
//! (`ghost-issuer --restore-wallet`).

use std::collections::{BTreeMap, BTreeSet};

use ghost_entitlement::grid::week;

use crate::invoice::{self, REORG_MARGIN_BLOCKS};
use crate::rail::{IncomingEntry, RailError, RailHeight};
use crate::reconcile::{self, CounterId};
use crate::service::{Issuer, TickOutcome};
use crate::store::{self, InvoiceRow, InvoiceState, MetaKey, PayWith, StoreError, Table, WriteTx};

/// What one tick did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TickReport {
    /// The view was synced (EXPIRED decisions and unattributed revenue were possible).
    pub synced_view: bool,
    /// Invoices whose row changed.
    pub changed: usize,
    pub purged: usize,
    pub reorg_after_issue: u64,
    pub unattributed_atomic: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TickError {
    Rail(RailError),
    Store(StoreError),
    /// The wallet holds fewer subaddresses than `highest_minor + 1`: nothing was decided.
    WalletIncomplete,
}

impl From<StoreError> for TickError {
    fn from(e: StoreError) -> Self {
        TickError::Store(e)
    }
}

impl Issuer {
    /// One scanner tick at `now` (§7.3).
    pub fn scan_tick_at(&self, now: u64) -> Result<TickReport, TickError> {
        if self.is_halted() {
            return Err(TickError::Store(StoreError::Db));
        }
        let h = match self.rail.height() {
            Ok(h) => h,
            Err(e) => {
                self.record_tick(now, TickOutcome::Failed(e), None);
                return Err(TickError::Rail(e));
            }
        };
        let count = match self.rail.address_count() {
            Ok(count) => u64::from(count),
            Err(e) => {
                self.record_tick(now, TickOutcome::Failed(e), Some(h));
                return Err(TickError::Rail(e));
            }
        };
        let c = u64::from(self.schedule.constants().confirmations);
        let (rows, scan_final, highest) = {
            let tx = self.store.read()?;
            (
                store::invoices(&*tx)?,
                store::meta(&*tx, MetaKey::ScanFinalHeight)?,
                store::meta(&*tx, MetaKey::HighestMinor)?.unwrap_or(0),
            )
        };
        if count <= highest {
            // A restore without the replay: the wallet cannot see every minor handed out.
            self.record_tick(now, TickOutcome::WalletIncomplete, Some(h));
            return Err(TickError::WalletIncomplete);
        }
        let mut from = scan_final.map_or(h.wallet.saturating_sub(c), |f| f.saturating_add(1));
        for (_, row) in &rows {
            if row.pay_with == PayWith::Monero && row.state.is_open() {
                from = from.min(row.created_height.saturating_sub(REORG_MARGIN_BLOCKS));
            }
        }
        let xs = match self.rail.transfers(from, h.wallet) {
            Ok(xs) => xs,
            Err(e) => {
                self.record_tick(now, TickOutcome::Failed(e), Some(h));
                return Err(TickError::Rail(e));
            }
        };
        let report = self.apply_tick(now, &h, from, &xs)?;
        let outcome = if h.synced_view() {
            TickOutcome::Synced
        } else {
            TickOutcome::Unsynced
        };
        self.record_tick(now, outcome, Some(h));
        Ok(report)
    }

    fn apply_tick(
        &self,
        now: u64,
        h: &RailHeight,
        from: u64,
        xs: &[IncomingEntry],
    ) -> Result<TickReport, StoreError> {
        let c = u64::from(self.schedule.constants().confirmations);
        let mut report = TickReport {
            synced_view: h.synced_view(),
            ..TickReport::default()
        };
        let mut tx = self.store.write()?;
        // Fresh rows inside the transaction: nothing interleaves with this read-modify-write.
        let rows: BTreeMap<[u8; 16], InvoiceRow> = store::invoices(&*tx)?.into_iter().collect();
        let mut recorded: BTreeMap<[u8; 16], Vec<([u8; 32], u64)>> = BTreeMap::new();
        for (id, row) in &rows {
            if row.pay_with == PayWith::Monero {
                recorded.insert(*id, store::credited_txs(&*tx, id)?);
            }
        }
        let txids = |id: &[u8; 16]| -> BTreeSet<[u8; 32]> {
            recorded
                .get(id)
                .map(|r| r.iter().map(|(t, _)| *t).collect())
                .unwrap_or_default()
        };

        // Unattributed revenue over heights that became final (§19.6 rule 2), before any purge.
        let scan_final = store::meta(&*tx, MetaKey::ScanFinalHeight)?;
        if h.synced_view() {
            let final_to = h.wallet.saturating_sub(c);
            if let Some(done) = scan_final {
                let mut amount = 0u64;
                for t in xs {
                    let Some(th) = t.height else { continue };
                    if th <= done
                        || th > final_to
                        || t.minor == 0
                        || t.unlock_time != 0
                        || t.double_spend_seen
                        || t.confirmations < c
                    {
                        continue;
                    }
                    let attributed = match store::minor_index(&*tx, t.minor)? {
                        Some(id) => rows.get(&id).is_some_and(|row| {
                            row.state != InvoiceState::Expired
                                && invoice::credits_invoice(row, t, &txids(&id))
                        }),
                        None => false,
                    };
                    if !attributed {
                        amount = amount.saturating_add(t.amount_atomic);
                    }
                }
                reconcile::add(&mut *tx, CounterId::UnattributedAtomic, week(now), amount)?;
                report.unattributed_atomic = amount;
            }
            let mark = scan_final.map_or(final_to, |done| done.max(final_to));
            store::set_meta(&mut *tx, MetaKey::ScanFinalHeight, mark)?;
        }

        let mut expired_credit = 0u64;
        for (id, row) in &rows {
            let mut next = row.clone();
            // Heights a credits-paid invoice or a journal replay could not know yet.
            if row.pay_with == PayWith::Credits
                && row.state == InvoiceState::Confirmed
                && row.confirmed_height == 0
            {
                next.confirmed_height = h.wallet;
            }
            if row.state == InvoiceState::Issued && row.issued_height == 0 {
                next.issued_height = h.wallet;
            }
            // Recompute only invoices whose whole range the fetched view covers.
            if row.pay_with == PayWith::Monero
                && row.created_height.saturating_sub(REORG_MARGIN_BLOCKS) >= from
            {
                let rec = recorded.get(id).cloned().unwrap_or_default();
                let a = invoice::amounts(row, xs, c, &txids(id));
                match row.state {
                    InvoiceState::Created | InvoiceState::Seen | InvoiceState::Confirmed => {
                        next = invoice::recompute(&next, &a, h, c, &txids(id));
                        if next.state == InvoiceState::Expired {
                            // Revenue no invoice will use (§19.6 rule 2).
                            expired_credit = expired_credit.saturating_add(next.credited);
                        }
                        for (txid, th) in &a.credited_txids {
                            let known = rec.iter().find(|(t, _)| t == txid).map(|(_, x)| *x);
                            if known != Some(*th) {
                                tx.put(
                                    Table::CreditedTx,
                                    &store::credited_key(id, txid),
                                    &th.to_be_bytes(),
                                )?;
                            }
                        }
                    }
                    InvoiceState::Issued => {
                        next.credited = a.credited;
                        next.seen = a.seen;
                        // A credited txid that vanished or moved after issuance: a financial
                        // residue (tokens stay valid, no claw-back), counted once per change.
                        for (txid, th) in &rec {
                            let key = store::credited_key(id, txid);
                            let current = xs
                                .iter()
                                .find(|t| t.txid == *txid && t.minor == row.minor)
                                .and_then(|t| t.height);
                            match current {
                                Some(x) if x == *th => {}
                                Some(x) => {
                                    report.reorg_after_issue += 1;
                                    tx.put(Table::CreditedTx, &key, &x.to_be_bytes())?;
                                }
                                None => {
                                    report.reorg_after_issue += 1;
                                    tx.delete(Table::CreditedTx, &key)?;
                                }
                            }
                        }
                    }
                    InvoiceState::Expired => {}
                }
            }
            if invoice::purge_due(&next, h.wallet) {
                purge(&mut *tx, id, &next, now)?;
                report.purged += 1;
                continue;
            }
            if next != *row {
                store::put_invoice(&mut *tx, id, &next)?;
                report.changed += 1;
            }
        }
        reconcile::add(
            &mut *tx,
            CounterId::ReorgAfterIssue,
            week(now),
            report.reorg_after_issue,
        )?;
        reconcile::add(
            &mut *tx,
            CounterId::UnattributedAtomic,
            week(now),
            expired_credit,
        )?;
        report.unattributed_atomic = report.unattributed_atomic.saturating_add(expired_credit);
        tx.commit()?;
        Ok(report)
    }
}

/// Deletes an invoice with its indices and credited txids (§5.4 purge row), counting a
/// CONFIRMED-unissued purge (revenue kept, `confirmed_unissued`) and any overpayment.
fn purge(
    tx: &mut dyn WriteTx,
    id: &[u8; 16],
    row: &InvoiceRow,
    now: u64,
) -> Result<(), StoreError> {
    let w = week(now);
    let xmr = row.pay_with == PayWith::Monero;
    match row.state {
        InvoiceState::Confirmed => {
            reconcile::add(tx, CounterId::ConfirmedUnissued, w, 1)?;
            if xmr {
                reconcile::add(tx, CounterId::XmrCreditedAtomic, row.base_week, row.amount)?;
                reconcile::add(
                    tx,
                    CounterId::OverpaidAtomic,
                    w,
                    row.credited.saturating_sub(row.amount),
                )?;
            }
        }
        InvoiceState::Issued if xmr => {
            reconcile::add(
                tx,
                CounterId::OverpaidAtomic,
                w,
                row.credited.saturating_sub(row.amount),
            )?;
        }
        _ => {}
    }
    tx.delete(Table::Invoice, id)?;
    if store::claim_index(tx, &row.claim_hash)? == Some(*id) {
        tx.delete(Table::ClaimIndex, &row.claim_hash)?;
    }
    if row.minor != 0 && store::minor_index(tx, row.minor)? == Some(*id) {
        tx.delete(Table::MinorIndex, &row.minor.to_be_bytes())?;
    }
    for (txid, _) in store::credited_txs(tx, id)? {
        tx.delete(Table::CreditedTx, &store::credited_key(id, &txid))?;
    }
    Ok(())
}
