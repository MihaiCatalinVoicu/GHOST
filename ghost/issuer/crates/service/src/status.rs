//! `status.json` (Phase 8 design §6.5; ADR-26): the issuer writes no log lines. Operators read one
//! status file, rewritten atomically every 60 s, that holds only fixed enum codes, booleans and
//! aggregate numbers: no identifier, address, amount of one invoice, time finer than a week, or
//! free text can appear in it. `tests/status_vocabulary.rs` serialises every reachable status and
//! proves that no key or code outside [`KEYS`] and [`CODES`] appears.
//!
//! Recorded additions to the §6.5 list (S6 review): `PAYOUT_BATCHES_OPEN` and
//! `PAYOUT_OLDEST_BATCH_WEEKS` (a batch the workstation never acknowledges keeps its claims and
//! payout addresses, so its age is the alarm) and `PAYOUT_ACKS_REFUSED` (acknowledgement files the
//! last payout run refused). S12 review (CR-RF-1, §19.27): `REFRESH_REFUSED`, new `RefreshCredit`s
//! refused since the process started because their credit epoch's budget was spent (an honest
//! population never spends it: a refresh chain of a credit holder does).
//!
//! This module, `store.rs`, `journal.rs` and `payout.rs` are the only service modules that write
//! files (`issuer-output.sh`).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use ghost_entitlement::grid::week;

use crate::rail::RailError;
use crate::reconcile::{self, CounterId};
use crate::service::{Issuer, TickOutcome};
use crate::store::{self, BatchState, ClaimState, InvoiceState, StoreError};

/// File name of the status file in the issuer's data directory.
pub const STATUS_FILE_NAME: &str = "status.json";
/// A scanner whose last tick is older than this is reported stalled (ticks run every 30 s ± 10 s).
pub const STALL_SECS: u64 = 300;
/// Runbook R1 expects at least this many pool entries.
pub const POOL_LOW_BELOW: usize = 16;
/// `OPEN_INVOICES` is rounded down to a multiple of this.
pub const OPEN_INVOICES_BUCKET: u64 = 100;

/// Every key of the status object, in output order.
pub const KEYS: [&str; 17] = [
    "SCANNER",
    "KEYS_READY_UNTIL_WEEK",
    "ES_HORIZON_WEEKS",
    "POOL_SIZE",
    "OPEN_INVOICES",
    "RECONCILIATION",
    "REORG_AFTER_ISSUE",
    "CONFIRMED_UNISSUED",
    "POOL_RECONCILED",
    "SIGN_FAULT",
    "KEYS_MISSING",
    "PAYOUT_BATCH_READY",
    "PAYOUT_BATCHES_OPEN",
    "PAYOUT_OLDEST_BATCH_WEEKS",
    "PAYOUT_ACKS_REFUSED",
    "REFRESH_REFUSED",
    "HALTED",
];

/// Every string value the status object can carry.
pub const CODES: [&str; 10] = [
    "SCANNER_OK",
    "SCANNER_STALLED",
    "WALLET_UNREACHABLE",
    "WALLET_INCOMPLETE",
    "REORG_DEPTH",
    "POOL_EMPTY",
    "POOL_LOW",
    "POOL_OK",
    "RECONCILIATION_OK",
    "MISMATCH",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScannerCode {
    Ok,
    Stalled,
    WalletUnreachable,
    /// The wallet was restored without runbook R5's replay: run `ghost-issuer --restore-wallet`.
    WalletIncomplete,
    ReorgDepth,
}

impl ScannerCode {
    pub const ALL: [ScannerCode; 5] = [
        ScannerCode::Ok,
        ScannerCode::Stalled,
        ScannerCode::WalletUnreachable,
        ScannerCode::WalletIncomplete,
        ScannerCode::ReorgDepth,
    ];

    pub fn code(self) -> &'static str {
        match self {
            ScannerCode::Ok => "SCANNER_OK",
            ScannerCode::Stalled => "SCANNER_STALLED",
            ScannerCode::WalletUnreachable => "WALLET_UNREACHABLE",
            ScannerCode::WalletIncomplete => "WALLET_INCOMPLETE",
            ScannerCode::ReorgDepth => "REORG_DEPTH",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PoolCode {
    Empty,
    Low,
    Ok,
}

impl PoolCode {
    pub const ALL: [PoolCode; 3] = [PoolCode::Empty, PoolCode::Low, PoolCode::Ok];

    pub fn code(self) -> &'static str {
        match self {
            PoolCode::Empty => "POOL_EMPTY",
            PoolCode::Low => "POOL_LOW",
            PoolCode::Ok => "POOL_OK",
        }
    }

    pub fn of(len: usize) -> Self {
        match len {
            0 => PoolCode::Empty,
            n if n < POOL_LOW_BELOW => PoolCode::Low,
            _ => PoolCode::Ok,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReconciliationCode {
    Ok,
    Mismatch,
}

impl ReconciliationCode {
    pub const ALL: [ReconciliationCode; 2] = [ReconciliationCode::Ok, ReconciliationCode::Mismatch];

    pub fn code(self) -> &'static str {
        match self {
            ReconciliationCode::Ok => "RECONCILIATION_OK",
            ReconciliationCode::Mismatch => "MISMATCH",
        }
    }
}

/// One status snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    pub scanner: ScannerCode,
    /// Last access week from the current one whose keys (with the invite and credit keys of those
    /// weeks) are all held; 0 when the current week is not ready.
    pub keys_ready_until_week: u64,
    /// Access weeks the issuer's ES still covers from the current week (runbook K2 alarm < 8).
    pub es_horizon_weeks: u64,
    pub pool: PoolCode,
    /// CREATED, SEEN and CONFIRMED invoices, rounded down to a multiple of 100.
    pub open_invoices: u64,
    pub reconciliation: ReconciliationCode,
    /// This week's counters.
    pub reorg_after_issue: u64,
    pub confirmed_unissued: u64,
    pub pool_reconciled: u64,
    /// Since the process started.
    pub sign_fault: u64,
    pub keys_missing: u64,
    /// Queued claims wait for the weekly batch.
    pub payout_batch_ready: bool,
    /// Exported batches waiting for the workstation's acknowledgement (runbook P1).
    pub payout_batches_open: u64,
    /// Weeks since the oldest of them was created (0 when none is open): a batch that is never
    /// acknowledged keeps its claims and payout addresses, so its age is the alarm.
    pub payout_oldest_batch_weeks: u64,
    /// Acknowledgement files the last payout run refused (they do not match an exported batch or
    /// cannot be read).
    pub payout_acks_refused: u64,
    /// Since the process started: new `RefreshCredit`s refused because their credit epoch's
    /// budget was spent (§19.27).
    pub refresh_refused: u64,
    /// A failure between a journal append and its commit halted the issuer (restart required).
    pub halted: bool,
}

impl StatusReport {
    /// One JSON object on one line, keys in [`KEYS`] order.
    pub fn to_json(&self) -> String {
        let s = |code: &str| format!("\"{code}\"");
        let values = [
            s(self.scanner.code()),
            self.keys_ready_until_week.to_string(),
            self.es_horizon_weeks.to_string(),
            s(self.pool.code()),
            self.open_invoices.to_string(),
            s(self.reconciliation.code()),
            self.reorg_after_issue.to_string(),
            self.confirmed_unissued.to_string(),
            self.pool_reconciled.to_string(),
            self.sign_fault.to_string(),
            self.keys_missing.to_string(),
            self.payout_batch_ready.to_string(),
            self.payout_batches_open.to_string(),
            self.payout_oldest_batch_weeks.to_string(),
            self.payout_acks_refused.to_string(),
            self.refresh_refused.to_string(),
            self.halted.to_string(),
        ];
        let fields: Vec<String> = KEYS
            .iter()
            .zip(values)
            .map(|(k, v)| format!("\"{k}\":{v}"))
            .collect();
        format!("{{{}}}\n", fields.join(","))
    }
}

/// Writes the status file atomically: a temporary file next to it, synced, then renamed over it.
pub fn write_status_file(path: &Path, report: &StatusReport) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    file.write_all(report.to_json().as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)
}

impl Issuer {
    /// The status at `now` (§6.5).
    pub fn status_at(&self, now: u64) -> Result<StatusReport, StoreError> {
        let w = week(now);
        let (scanner, sign_fault, keys_missing, payout_acks_refused, refresh_refused) = {
            let v = self.volatile();
            let scanner = match v.last_tick {
                None => ScannerCode::Stalled,
                Some(t) if now.saturating_sub(t.at) > STALL_SECS => ScannerCode::Stalled,
                Some(t) => match t.outcome {
                    TickOutcome::Synced => ScannerCode::Ok,
                    TickOutcome::Unsynced => ScannerCode::Stalled,
                    TickOutcome::WalletIncomplete => ScannerCode::WalletIncomplete,
                    TickOutcome::Failed(RailError::ReorgDepth) => ScannerCode::ReorgDepth,
                    TickOutcome::Failed(_) => ScannerCode::WalletUnreachable,
                },
            };
            (
                scanner,
                v.sign_faults,
                v.keys_missing,
                v.payout_acks_refused,
                v.refresh_refused,
            )
        };
        let tx = self.store.read()?;
        let open = store::invoices(&*tx)?
            .iter()
            .filter(|(_, r)| {
                matches!(
                    r.state,
                    InvoiceState::Created | InvoiceState::Seen | InvoiceState::Confirmed
                )
            })
            .count() as u64;
        let counters = reconcile::all(&*tx)?;
        let this_week = |id: CounterId| counters.get(&(id, w)).copied().unwrap_or(0);
        let mismatches = reconcile::check(&counters, &self.schedule, now);
        let open_batches: Vec<u64> = store::batches(&*tx)?
            .into_iter()
            .filter(|(_, b)| b.state == BatchState::Exported)
            .map(|(_, b)| b.week)
            .collect();
        Ok(StatusReport {
            scanner,
            keys_ready_until_week: self.keys().ready_until_week(w).unwrap_or(0),
            es_horizon_weeks: self
                .schedule
                .last_access_week()
                .saturating_add(1)
                .saturating_sub(w),
            pool: PoolCode::of(store::pool(&*tx)?.len()),
            open_invoices: open / OPEN_INVOICES_BUCKET * OPEN_INVOICES_BUCKET,
            reconciliation: if mismatches.is_empty() {
                ReconciliationCode::Ok
            } else {
                ReconciliationCode::Mismatch
            },
            reorg_after_issue: this_week(CounterId::ReorgAfterIssue),
            confirmed_unissued: this_week(CounterId::ConfirmedUnissued),
            pool_reconciled: this_week(CounterId::PoolReconciled),
            sign_fault,
            keys_missing,
            payout_batch_ready: store::claims(&*tx)?
                .iter()
                .any(|(_, c)| c.state == ClaimState::Queued),
            payout_batches_open: open_batches.len() as u64,
            payout_oldest_batch_weeks: open_batches
                .iter()
                .min()
                .map_or(0, |&oldest| w.saturating_sub(oldest)),
            payout_acks_refused,
            refresh_refused,
            halted: self.is_halted(),
        })
    }
}
