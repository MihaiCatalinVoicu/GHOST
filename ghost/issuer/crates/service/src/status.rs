//! `status.json` (Phase 8 design §6.5; ADR-26): the issuer writes no log lines. Operators read one
//! status file, rewritten atomically every 60 s, that holds only fixed enum codes, booleans and
//! aggregate numbers: no identifier, address, amount of one invoice, time finer than a week, or
//! free text can appear in it. `tests/status_vocabulary.rs` serialises every reachable status and
//! proves that no key or code outside [`KEYS`] and [`CODES`] appears.
//!
//! This module, `store.rs` and `journal.rs` are the only service modules that write files
//! (`issuer-output.sh`).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use ghost_entitlement::grid::week;

use crate::rail::RailError;
use crate::reconcile::{self, CounterId};
use crate::service::{Issuer, TickOutcome};
use crate::store::{self, ClaimState, InvoiceState, StoreError};

/// File name of the status file in the issuer's data directory.
pub const STATUS_FILE_NAME: &str = "status.json";
/// A scanner whose last tick is older than this is reported stalled (ticks run every 30 s ± 10 s).
pub const STALL_SECS: u64 = 300;
/// Runbook R1 expects at least this many pool entries.
pub const POOL_LOW_BELOW: usize = 16;
/// `OPEN_INVOICES` is rounded down to a multiple of this.
pub const OPEN_INVOICES_BUCKET: u64 = 100;

/// Every key of the status object, in output order.
pub const KEYS: [&str; 13] = [
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
    "HALTED",
];

/// Every string value the status object can carry.
pub const CODES: [&str; 9] = [
    "SCANNER_OK",
    "SCANNER_STALLED",
    "WALLET_UNREACHABLE",
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
    ReorgDepth,
}

impl ScannerCode {
    pub const ALL: [ScannerCode; 4] = [
        ScannerCode::Ok,
        ScannerCode::Stalled,
        ScannerCode::WalletUnreachable,
        ScannerCode::ReorgDepth,
    ];

    pub fn code(self) -> &'static str {
        match self {
            ScannerCode::Ok => "SCANNER_OK",
            ScannerCode::Stalled => "SCANNER_STALLED",
            ScannerCode::WalletUnreachable => "WALLET_UNREACHABLE",
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
        let (scanner, sign_fault, keys_missing) = {
            let v = self.volatile();
            let scanner = match v.last_tick {
                None => ScannerCode::Stalled,
                Some(t) if now.saturating_sub(t.at) > STALL_SECS => ScannerCode::Stalled,
                Some(t) => match t.outcome {
                    TickOutcome::Synced => ScannerCode::Ok,
                    TickOutcome::Unsynced => ScannerCode::Stalled,
                    TickOutcome::Failed(RailError::ReorgDepth) => ScannerCode::ReorgDepth,
                    TickOutcome::Failed(_) => ScannerCode::WalletUnreachable,
                },
            };
            (scanner, v.sign_faults, v.keys_missing)
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
            halted: self.is_halted(),
        })
    }
}
