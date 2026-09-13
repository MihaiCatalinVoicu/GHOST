//! `reconcile-check` and `counters-export` (design §6.9, §19.3, §19.7; runbook R2).
//!
//! The reconciliation reads the issuer's counters: aggregates without identifiers (§6.9). They
//! come from one of two places, and the tool never combines the issuer's database with the payout
//! workstation's files:
//!
//! - on the issuer host, `reconcile-check --database <snapshot copy>` reads them from a snapshot of
//!   `issuer.redb` (never the live database, which the issuer holds open), optionally with the
//!   relay operators' counts;
//! - `counters-export --database <snapshot copy> --out <file>`, also on the issuer host, writes
//!   the counters alone to a counters file, and on the workstation `reconcile-check --counters
//!   <file>` checks them with the relay counts and with the workstation's own view dump and ledger
//!   (`--view-dump` and `--ledger` are refused with `--database`).
//!
//! A snapshot copy therefore never leaves the issuer host, where the snapshot retention of §19.15
//! point 1 covers it, and no issuer identifier reaches the workstation: the counters file carries
//! only what §6.4 keeps 400 days as aggregates, and runbook R2 deletes it after the check.
//!
//! Checked: the invariants of the counters; the per-week redemption counts the relay operators
//! report (the sum over all slots of week w within `access_per_slot·|slots(w)|·(packs covering w) +
//! trial_per_slot·|slots(w)|·(trials covering w)`); and the payout workstation's view dump (the
//! issuer's cumulative credited revenue not above what the view received since the treasury's
//! restore height, and the ledger's cumulative payouts within 10 % of it), the checks a
//! compromised issuer cannot fake. One line per mismatch; the exit status is 1 when there is any.
//!
//! ```text
//! relay counts file := lines "week <w> slot <s> redemptions <n>", "#" comments and blank lines;
//!                      a (week, slot) is reported once over all files
//! counters file     := "ghost-issuer-counters 1" LF, then one "<counter code> <index> <value>" LF
//!                      per counter, ascending by (code, index), canonical decimals
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ghost_issuer::reconcile::{self, CounterId, Counters, TOTAL_INDEX};
use ghost_issuer::store::RedbSnapshot;

use crate::args::{parse_u64, Flags};
use crate::input::{input_refused, read_text};
use crate::output;
use crate::report::{mismatch_line, Code, Field, Line, Sink};
use crate::schedule_verify::load_schedule;
use crate::workstation::{load_ledger, view_incoming};
use crate::Failure;

/// The first line of a counters file.
pub const COUNTERS_HEADER: &str = "ghost-issuer-counters 1";

const FLAGS: [&str; 9] = [
    "database",
    "counters",
    "schedule",
    "schedule-public-key",
    "now",
    "relay-counts",
    "view-dump",
    "restore-height",
    "ledger",
];

/// The flags of the workstation's inputs, refused next to `--database`.
const WORKSTATION_FLAGS: [&str; 4] = ["counters", "view-dump", "restore-height", "ledger"];

const EXPORT_FLAGS: [&str; 2] = ["database", "out"];

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

/// The counters of a snapshot copy of `issuer.redb`.
fn snapshot_counters(path: &Path) -> Result<Counters, Failure> {
    let snapshot = RedbSnapshot::open(path)
        .map_err(|_| Failure::refused(input_refused("database", "open")))?;
    let tx = snapshot
        .read()
        .map_err(|_| Failure::refused(input_refused("database", "read")))?;
    let counters =
        reconcile::all(&*tx).map_err(|_| Failure::refused(input_refused("database", "read")))?;
    Ok(counters)
}

/// The counters file of `counters`.
pub fn encode_counters(counters: &Counters) -> String {
    let mut out = format!("{COUNTERS_HEADER}\n");
    for ((id, index), value) in counters {
        out.push_str(&format!("{} {index} {value}\n", id.code()));
    }
    out
}

/// A counters file, strictly: its header, then lines of known counters in ascending
/// (code, index) order, each ended by a newline.
pub fn parse_counters(text: &str) -> Result<Counters, Failure> {
    let refused = |reason: &'static str, line: u64| {
        Failure::refused(input_refused("counters", reason).num(Field::Line, line))
    };
    let mut lines = text.split_inclusive('\n');
    let header = format!("{COUNTERS_HEADER}\n");
    if lines.next() != Some(header.as_str()) {
        return Err(refused("header", 1));
    }
    let mut counters = Counters::new();
    let mut last: Option<(u8, u64)> = None;
    for (i, line) in lines.enumerate() {
        let n = i as u64 + 2;
        let words: Vec<&str> = line
            .strip_suffix('\n')
            .ok_or_else(|| refused("line", n))?
            .split(' ')
            .collect();
        let [code, index, value] = words.as_slice() else {
            return Err(refused("line", n));
        };
        let code = parse_u64(code)
            .and_then(|c| u8::try_from(c).ok())
            .ok_or_else(|| refused("line", n))?;
        let id = CounterId::from_code(code).ok_or_else(|| refused("line", n))?;
        let index = parse_u64(index).ok_or_else(|| refused("line", n))?;
        let value = parse_u64(value).ok_or_else(|| refused("line", n))?;
        if last.is_some_and(|l| l >= (code, index)) {
            return Err(refused("order", n));
        }
        last = Some((code, index));
        counters.insert((id, index), value);
    }
    Ok(counters)
}

/// `counters-export`: the counters of a snapshot copy, alone, in a new counters file.
pub fn export(argv: &[String], sink: &mut dyn Sink) -> Result<(), Failure> {
    let flags = Flags::parse(argv, &EXPORT_FLAGS)?;
    let out = flags.path("out")?;
    let counters = snapshot_counters(&flags.path("database")?)?;
    output::write_counters(&out, &encode_counters(&counters), "out")?;
    sink.emit(Line::new(Code::CountersWritten).num(Field::Counters, counters.len() as u64));
    Ok(())
}

pub fn run(argv: &[String], sink: &mut dyn Sink) -> Result<(), Failure> {
    let flags = Flags::parse_repeatable(argv, &FLAGS, &["relay-counts"])?;
    let now = flags.u64("now")?;
    let counters = if flags.has("database") {
        if let Some(extra) = WORKSTATION_FLAGS.into_iter().find(|f| flags.has(f)) {
            return Err(Failure::usage("conflicting-flags", Some(extra)));
        }
        snapshot_counters(&flags.path("database")?)?
    } else {
        if flags.has("ledger") && !flags.has("view-dump") {
            return Err(Failure::usage("missing-flag", Some("view-dump")));
        }
        parse_counters(&read_text(&flags.path("counters")?, "counters")?)?
    };
    let schedule = load_schedule(&flags, "schedule")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_counters_file_round_trips_and_is_read_strictly() {
        let mut counters = Counters::new();
        counters.insert((CounterId::PacksXmr, 2960), 1);
        counters.insert((CounterId::SignedAccess, 2961), 48);
        counters.insert((CounterId::XmrCreditedTotal, TOTAL_INDEX), 200);
        let text = encode_counters(&counters);
        assert_eq!(
            text,
            "ghost-issuer-counters 1\n1 2960 1\n7 2961 48\n19 0 200\n"
        );
        assert_eq!(parse_counters(&text).unwrap(), counters);
        let reason = |text: &str| {
            let failure = parse_counters(text).unwrap_err();
            failure
                .line
                .fields
                .iter()
                .find(|(f, _)| *f == Field::Reason)
                .map(|(_, v)| v.clone())
        };
        use crate::report::Value::Word;
        for (bad, why) in [
            ("ghost-issuer-counters 2\n", "header"),
            ("", "header"),
            ("ghost-issuer-counters 1\n1 2960 1", "line"),
            ("ghost-issuer-counters 1\n99 2960 1\n", "line"),
            ("ghost-issuer-counters 1\n1 02960 1\n", "line"),
            ("ghost-issuer-counters 1\n1 2960 1 1\n", "line"),
            ("ghost-issuer-counters 1\n7 2961 48\n1 2960 1\n", "order"),
            ("ghost-issuer-counters 1\n1 2960 1\n1 2960 2\n", "order"),
        ] {
            assert_eq!(reason(bad), Some(Word(why)), "{bad:?}");
        }
    }
}
