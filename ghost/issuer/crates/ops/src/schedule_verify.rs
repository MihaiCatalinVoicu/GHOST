//! `schedule-verify` (design §3.1, §14.1, §19.12): what `entitlement-schedule.sh` runs on the
//! committed schedule. Rules 1-4 under the schedule key pinned in `ghost-entitlement` for the
//! schedule's network (`Schedule::verify`, the production entry point), or under an explicit key
//! for test schedules and for a schedule signed before its key is pinned; rule 5 over the earlier
//! versions (`--previous`, repeatable, oldest first: the git history), each checked against all
//! versions before it and the schedule against all of them; the relay directory check for the
//! current and the next week.

use ghost_entitlement::{Schedule, ScheduleError};

use crate::args::Flags;
use crate::directory::Directory;
use crate::input::{input_refused, read, read_text};
use crate::report::{network_name, schedule_error, Code, Field, Line, Sink};
use crate::schedule_sign::append_only;
use crate::Failure;

const FLAGS: [&str; 5] = [
    "schedule",
    "schedule-public-key",
    "previous",
    "relay-directory",
    "now",
];

pub(crate) fn es_refused(file: &'static str, e: ScheduleError) -> Failure {
    Failure::refused(
        Line::new(Code::EsRefused)
            .word(Field::File, file)
            .word(Field::Reason, schedule_error(e)),
    )
}

/// The summary fields of a verified schedule.
pub(crate) fn es_ok_line(code: Code, schedule: &Schedule) -> Line {
    let content = schedule.content();
    Line::new(code)
        .num(Field::Seq, schedule.seq())
        .word(Field::Network, network_name(schedule.network()))
        .num(Field::FirstWeek, schedule.first_access_week())
        .num(Field::LastWeek, schedule.last_access_week())
        .num(
            Field::Weeks,
            schedule.last_access_week() - schedule.first_access_week() + 1,
        )
        .num(Field::Keys, content.keys.len() as u64)
        .num(Field::Slots, content.slots.len() as u64)
        .hex(Field::Sha256, schedule.digest())
}

fn verify(bytes: &[u8], explicit_key: Option<&[u8; 32]>) -> Result<Schedule, ScheduleError> {
    match explicit_key {
        Some(key) => Schedule::verify_with_key(bytes, key),
        None => Schedule::verify(bytes),
    }
}

fn explicit_key(flags: &Flags) -> Result<Option<[u8; 32]>, Failure> {
    if flags.has("schedule-public-key") {
        flags.hex32("schedule-public-key").map(Some)
    } else {
        Ok(None)
    }
}

/// The schedule named by `flag`, verified under the pinned key or `--schedule-public-key`.
pub(crate) fn load_schedule(flags: &Flags, flag: &'static str) -> Result<Schedule, Failure> {
    let key = explicit_key(flags)?;
    verify(&read(&flags.path(flag)?, flag)?, key.as_ref()).map_err(|e| es_refused(flag, e))
}

pub fn run(argv: &[String], sink: &mut dyn Sink) -> Result<(), Failure> {
    let flags = Flags::parse_repeatable(argv, &FLAGS, &["previous"])?;
    let key = explicit_key(&flags)?;
    let directory_now = match (flags.has("relay-directory"), flags.has("now")) {
        (true, true) => Some((flags.path("relay-directory")?, flags.u64("now")?)),
        (false, false) => None,
        (true, false) => return Err(Failure::usage("missing-flag", Some("now"))),
        (false, true) => return Err(Failure::usage("missing-flag", Some("relay-directory"))),
    };
    let schedule = load_schedule(&flags, "schedule")?;
    let key_field = match &key {
        Some(k) => es_ok_line(Code::EsOk, &schedule).hex(Field::ScheduleKey, k),
        None => es_ok_line(Code::EsOk, &schedule).word(Field::ScheduleKey, "pinned"),
    };
    sink.emit(key_field);

    // A version committed before is not trusted for having been checked once: CI may never have
    // run on it (a push or a fast-forward merge brings several versions at once).
    let mut history: Vec<Schedule> = Vec::new();
    for path in flags.paths("previous") {
        let previous = verify(&read(&path, "previous")?, key.as_ref())
            .map_err(|e| es_refused("previous", e))?;
        append_only(&previous, "previous", &history)?;
        history.push(previous);
    }
    if let Some(last) = history.last() {
        append_only(&schedule, "schedule", &history)?;
        sink.emit(
            Line::new(Code::EsAppendOnly)
                .num(Field::PreviousSeq, last.seq())
                .num(Field::History, history.len() as u64),
        );
    }

    if let Some((path, now)) = directory_now {
        let text = read_text(&path, "relay-directory")?;
        let directory = Directory::parse(&text).map_err(|e| {
            Failure::refused(input_refused("relay-directory", e.reason).num(Field::Line, e.line))
        })?;
        let weeks = directory.check(&schedule, now).map_err(|f| {
            let mut line = Line::new(Code::DirectoryRefused)
                .word(Field::Reason, f.reason)
                .num(Field::Week, f.week);
            if let Some(slot) = f.slot {
                line = line.num(Field::Slot, u64::from(slot));
            }
            Failure::refused(line)
        })?;
        sink.emit(Line::new(Code::DirectoryOk).num(Field::Weeks, weeks));
    }
    Ok(())
}
