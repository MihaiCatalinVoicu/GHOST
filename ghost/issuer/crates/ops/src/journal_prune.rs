//! `journal-prune` (design §6.3, §6.4, §19.15; runbook B1): removes the `issued.journal` segments a
//! verified snapshot makes unnecessary, so the journal's retention of about 7–14 days holds.
//!
//! The snapshot is read through a recovered private copy (`RedbSnapshot`, as `reconcile-check`
//! reads it; the snapshot keeps its bytes) and is verified as runbook B1 defines it: it opens as
//! an issuer database of schema 1 and the reconciliation invariants of its counters hold at
//! `--now`. Only then does its `journal_applied` mark bound what goes:
//! `ghost_issuer::journal::prune_dir` removes, in ascending order, the segments before the one that
//! holds the journal's last entry whose entries are all older than the 7-day re-serve window and
//! applied in the snapshot (design §19.24), and
//! removes nothing when the snapshot does not fit the journal (it applied entries the journal does
//! not hold, or the journal no longer holds the entry after its last applied one, so a restore
//! from it would refuse the start). The journal's files are removed by the journal module, which
//! owns them (the `issuer-output` gate); no segment is opened for writing, so the issuer may be
//! appending to its latest segment meanwhile.
//!
//! ```text
//! SEGMENT_PRUNED week=<w>                     one per removed segment, ascending
//! JOURNAL_PRUNED removed=<n> kept=<k> first_seq=<s> last_seq=<s> applied=<a>
//! PRUNE_REFUSED reason=<r>                    snapshot-unverified (after one RECONCILIATION_MISMATCH
//!                                             line per violated invariant), snapshot-ahead,
//!                                             snapshot-behind, journal-io, journal-corrupt,
//!                                             journal-format, journal-gap
//! ```

use ghost_issuer::journal::{self, JournalError, PruneError};
use ghost_issuer::reconcile;

use crate::args::Flags;
use crate::reconcile_check::read_snapshot;
use crate::report::{mismatch_line, Code, Field, Line, Sink};
use crate::schedule_verify::load_schedule;
use crate::Failure;

const FLAGS: [&str; 5] = [
    "database",
    "journal",
    "schedule",
    "schedule-public-key",
    "now",
];

fn refused(reason: &'static str) -> Failure {
    Failure::refused(Line::new(Code::PruneRefused).word(Field::Reason, reason))
}

fn prune_reason(e: PruneError) -> &'static str {
    match e {
        PruneError::SnapshotAhead => "snapshot-ahead",
        PruneError::SnapshotBehind => "snapshot-behind",
        PruneError::Journal(JournalError::Io) => "journal-io",
        PruneError::Journal(JournalError::Corrupt) => "journal-corrupt",
        PruneError::Journal(JournalError::Format) => "journal-format",
        PruneError::Journal(JournalError::Gap) => "journal-gap",
    }
}

pub fn run(argv: &[String], sink: &mut dyn Sink) -> Result<(), Failure> {
    let flags = Flags::parse(argv, &FLAGS)?;
    let now = flags.u64("now")?;
    let journal_dir = flags.path("journal")?;
    let database = flags.path("database")?;
    let schedule = load_schedule(&flags, "schedule")?;
    let snapshot = read_snapshot(&database)?;
    let mismatches = reconcile::check(&snapshot.counters, &schedule, now);
    if !mismatches.is_empty() {
        for m in &mismatches {
            sink.emit(mismatch_line(m));
        }
        return Err(refused("snapshot-unverified"));
    }
    let pruned = journal::prune_dir(&journal_dir, now, snapshot.journal_applied)
        .map_err(|e| refused(prune_reason(e)))?;
    for week in &pruned.removed {
        sink.emit(Line::new(Code::SegmentPruned).num(Field::Week, *week));
    }
    sink.emit(
        Line::new(Code::JournalPruned)
            .num(Field::Removed, pruned.removed.len() as u64)
            .num(Field::Kept, pruned.kept as u64)
            .num(Field::FirstSeq, pruned.first_seq)
            .num(Field::LastSeq, pruned.last_seq)
            .num(Field::Applied, snapshot.journal_applied),
    );
    Ok(())
}
