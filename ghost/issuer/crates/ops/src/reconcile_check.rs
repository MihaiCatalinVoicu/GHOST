//! `reconcile-check` (design §6.9, §19.3, §19.7; runbook R2): the reconciliation invariants of a
//! snapshot of `issuer.redb` (never the live database), plus the independent checks a compromised
//! issuer cannot fake: the per-week redemption counts the relay operators report (the sum over
//! all slots of week w within `access_per_slot·|slots(w)|·(packs covering w) +
//! trial_per_slot·|slots(w)|·(trials covering w)`), and the payout workstation's view dump (the
//! issuer's cumulative credited revenue not above what the view received since the treasury's
//! restore height, and the ledger's cumulative payouts within 10 % of it). One line per mismatch;
//! the exit status is 1 when there is any.
//!
//! A relay counts file: `week <w> slot <s> redemptions <n>` lines, `#` comments and blank lines;
//! a (week, slot) is reported once over all files.

use std::collections::{BTreeMap, BTreeSet};

use ghost_issuer::reconcile::{self, CounterId, TOTAL_INDEX};
use ghost_issuer::store::RedbSnapshot;

use crate::args::{parse_u64, Flags};
use crate::input::{input_refused, read_text};
use crate::report::{mismatch_line, Code, Field, Line, Sink};
use crate::schedule_verify::load_schedule;
use crate::workstation::{load_ledger, view_incoming};
use crate::Failure;

const FLAGS: [&str; 8] = [
    "database",
    "schedule",
    "schedule-public-key",
    "now",
    "relay-counts",
    "view-dump",
    "restore-height",
    "ledger",
];

/// Adds one relay counts file to `sums` (week → redemptions over all slots).
fn add_relay_counts(
    text: &str,
    seen: &mut BTreeSet<(u64, u64)>,
    sums: &mut BTreeMap<u64, u64>,
) -> Result<(), Failure> {
    for (i, line) in text.lines().enumerate() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bad = || {
            Failure::refused(input_refused("relay-counts", "line").num(Field::Line, i as u64 + 1))
        };
        let words: Vec<&str> = line.split(' ').collect();
        let ["week", w, "slot", s, "redemptions", n] = words.as_slice() else {
            return Err(bad());
        };
        let (w, s, n) = (
            parse_u64(w).ok_or_else(bad)?,
            parse_u64(s).ok_or_else(bad)?,
            parse_u64(n).ok_or_else(bad)?,
        );
        if !seen.insert((w, s)) {
            return Err(Failure::refused(
                input_refused("relay-counts", "duplicate").num(Field::Line, i as u64 + 1),
            ));
        }
        let sum = sums.entry(w).or_default();
        *sum = sum.checked_add(n).ok_or_else(bad)?;
    }
    Ok(())
}

pub fn run(argv: &[String], sink: &mut dyn Sink) -> Result<(), Failure> {
    let flags = Flags::parse_repeatable(argv, &FLAGS, &["relay-counts"])?;
    let now = flags.u64("now")?;
    if flags.has("ledger") && !flags.has("view-dump") {
        return Err(Failure::usage("missing-flag", Some("view-dump")));
    }
    let schedule = load_schedule(&flags, "schedule")?;
    let snapshot = RedbSnapshot::open(&flags.path("database")?)
        .map_err(|_| Failure::refused(input_refused("database", "open")))?;
    let tx = snapshot
        .read()
        .map_err(|_| Failure::refused(input_refused("database", "read")))?;
    let counters =
        reconcile::all(&*tx).map_err(|_| Failure::refused(input_refused("database", "read")))?;
    let mut mismatches = reconcile::check(&counters, &schedule, now);

    let relay_files = flags.paths("relay-counts");
    let mut seen = BTreeSet::new();
    let mut sums = BTreeMap::new();
    for path in &relay_files {
        add_relay_counts(&read_text(path, "relay-counts")?, &mut seen, &mut sums)?;
    }
    mismatches.extend(reconcile::check_relays(&counters, &schedule, now, &sums));

    if flags.has("view-dump") {
        let incoming = view_incoming(&flags.path("view-dump")?, flags.u64("restore-height")?)?;
        let paid_so_far = match flags.opt_path("ledger") {
            Some(path) => load_ledger(&path)?
                .ok_or(Failure::refused(input_refused("ledger", "missing")))?
                .paid_so_far(),
            None => 0,
        };
        let credited = counters
            .get(&(CounterId::XmrCreditedTotal, TOTAL_INDEX))
            .copied()
            .unwrap_or(0);
        mismatches.extend(reconcile::check_view(credited, incoming, paid_so_far));
    }

    let Some((last, rest)) = mismatches.split_last() else {
        sink.emit(
            Line::new(Code::ReconciliationOk)
                .num(Field::Weeks, sums.len() as u64)
                .num(Field::Relays, relay_files.len() as u64),
        );
        return Ok(());
    };
    for m in rest {
        sink.emit(mismatch_line(m));
    }
    Err(Failure::refused(mismatch_line(last)))
}
