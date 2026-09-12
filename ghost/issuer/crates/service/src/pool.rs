//! The subaddress pool (Phase 8 design §7.2, §19.5 rule 3, §19.6 rule 4): `RequestInvoice` takes
//! the lowest-minor entry inside its transaction and never waits on the wallet.
//!
//! - **Reconciliation** before the first refill of a process (and after a restore, whose pool was
//!   emptied at startup): `highest_minor := max(highest_minor, wallet subaddress count − 1)`, so
//!   the pool is always refilled above every minor the wallet ever created.
//! - **Refill**: `create_address` → `(m, address)`, validated locally (subaddress of the ES
//!   network, Keccak-256 checksum, both keys decompress); `m = highest_minor + 1` is required.
//!   On a mismatch (the lost response of an earlier call) the reconciliation runs in the process
//!   (counter `POOL_RECONCILED`) and refilling continues; `m` itself is kept only if it is the
//!   newest minor and above every earlier one. A crash between the call and the commit only burns
//!   an index.

use ghost_entitlement::grid::week;
use ghost_entitlement::monero::{AddressPurpose, MoneroAddress};

use crate::rail::RailError;
use crate::reconcile::{self, CounterId};
use crate::service::Issuer;
use crate::store::{self, MetaKey, StoreError, Table, ADDRESS_LEN};

/// What one refill did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PoolReport {
    pub added: u32,
    /// Minors created by the wallet but not added (lost responses, non-newest minors).
    pub burned: u32,
    /// `highest_minor` was reconciled with the wallet during this refill.
    pub reconciled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PoolError {
    Rail(RailError),
    Store(StoreError),
    /// The wallet returned an address that does not validate for invoices (§7.7).
    AddressRejected,
    Halted,
}

impl From<StoreError> for PoolError {
    fn from(e: StoreError) -> Self {
        PoolError::Store(e)
    }
}

impl From<RailError> for PoolError {
    fn from(e: RailError) -> Self {
        PoolError::Rail(e)
    }
}

impl Issuer {
    /// Refills the pool up to its target (§7.2; every 60 s while below target).
    pub fn pool_refill_at(&self, now: u64) -> Result<PoolReport, PoolError> {
        if self.is_halted() {
            return Err(PoolError::Halted);
        }
        let mut report = PoolReport::default();
        if !self.volatile().reconciled {
            let count = self.rail.address_count()?;
            self.raise_highest(u64::from(count).saturating_sub(1), false, now)?;
            self.volatile().reconciled = true;
            report.reconciled = true;
        }
        // At most two wallet calls per pool slot in one run: a wallet that keeps answering stale
        // minors cannot hold the refill job (the next run continues).
        let mut attempts = self.params.pool_target.saturating_mul(2).max(1);
        loop {
            let (len, highest) = {
                let tx = self.store.read()?;
                (
                    store::pool(&*tx)?.len(),
                    store::meta(&*tx, MetaKey::HighestMinor)?.unwrap_or(0),
                )
            };
            if len >= self.params.pool_target as usize || attempts == 0 {
                return Ok(report);
            }
            attempts -= 1;
            let (m, text) = self.rail.new_address()?;
            let m = u64::from(m);
            let valid = text.len() == ADDRESS_LEN
                && MoneroAddress::parse(&text, self.schedule.network(), AddressPurpose::Invoice)
                    .is_ok();
            if !valid {
                return Err(PoolError::AddressRejected);
            }
            let accept = if m == highest.saturating_add(1) {
                true
            } else {
                // A lost response of an earlier call: reconcile in the process (§19.6 rule 4).
                let count = u64::from(self.rail.address_count()?);
                let reconciled = highest.max(count.saturating_sub(1));
                self.raise_highest(reconciled, true, now)?;
                report.reconciled = true;
                m > highest && m == reconciled
            };
            let mut tx = self.store.write()?;
            let current = store::meta(&*tx, MetaKey::HighestMinor)?.unwrap_or(0);
            // m is fresh: above every minor known before this call (both branches of `accept`
            // imply m > highest), and never below a mark raised since.
            if accept && m > 0 && m >= current {
                let mut address = [0u8; ADDRESS_LEN];
                address.copy_from_slice(text.as_bytes());
                tx.put(Table::AddressPool, &(m as u32).to_be_bytes(), &address)?;
                store::set_meta(&mut *tx, MetaKey::HighestMinor, current.max(m))?;
                report.added += 1;
            } else {
                report.burned += 1;
            }
            tx.commit()?;
        }
    }

    /// `highest_minor := max(highest_minor, to)`, counting an in-process reconciliation.
    fn raise_highest(&self, to: u64, count_alarm: bool, now: u64) -> Result<(), StoreError> {
        let mut tx = self.store.write()?;
        let current = store::meta(&*tx, MetaKey::HighestMinor)?.unwrap_or(0);
        store::set_meta(&mut *tx, MetaKey::HighestMinor, current.max(to))?;
        if count_alarm {
            reconcile::add(&mut *tx, CounterId::PoolReconciled, week(now), 1)?;
        }
        tx.commit()
    }
}
