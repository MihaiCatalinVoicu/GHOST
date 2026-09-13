//! `schedule-onions` (design §3.1 rule 4, §19.10 point 3, §19.21 point 1; runbooks "Instalare" and
//! O1): the onions a verified Entitlement Schedule names, in the report vocabulary, so an operator
//! compares the `hostname` file Tor wrote with the schedule's `issuer_onion` itself (a search of the
//! schedule's bytes also matches a relay's onion listed with the same port).
//!
//! ```text
//! ISSUER_ONION onion=<56 base32>.onion port=<p>
//! SLOT_ONION week=<w> slot=<s> onion=<56 base32>.onion port=<p>
//! ```
//! With `--now`, one `SLOT_ONION` line per slot of the current and of the next week (the weeks a
//! relay's start-up check and the relay directory check look at), ascending by week and slot.

use ghost_entitlement::grid::week;
use ghost_entitlement::onion::Onion;
use ghost_entitlement::ScheduleError;

use crate::args::Flags;
use crate::report::{Code, Field, Line, Sink};
use crate::schedule_verify::{es_refused, load_schedule};
use crate::Failure;

const FLAGS: [&str; 3] = ["schedule", "schedule-public-key", "now"];

/// A verified schedule holds canonical onions only (rule 4); anything else is refused as such.
fn parse(text: &str) -> Result<Onion, Failure> {
    Onion::parse(text).map_err(|_| es_refused("schedule", ScheduleError::Onion))
}

pub fn run(argv: &[String], sink: &mut dyn Sink) -> Result<(), Failure> {
    let flags = Flags::parse(argv, &FLAGS)?;
    let now = if flags.has("now") {
        Some(flags.u64("now")?)
    } else {
        None
    };
    let schedule = load_schedule(&flags, "schedule")?;
    let issuer = parse(&schedule.content().issuer_onion)?;
    sink.emit(
        Line::new(Code::IssuerOnion)
            .onion(Field::Onion, &issuer.pubkey)
            .num(Field::Port, u64::from(issuer.port)),
    );
    if let Some(now) = now {
        let current = week(now);
        for w in [current, current.saturating_add(1)] {
            for slot in schedule.slots_in_week(w) {
                let Some(text) = schedule.slot_onion(slot, w) else {
                    continue;
                };
                let onion = parse(text)?;
                sink.emit(
                    Line::new(Code::SlotOnion)
                        .num(Field::Week, w)
                        .num(Field::Slot, u64::from(slot))
                        .onion(Field::Onion, &onion.pubkey)
                        .num(Field::Port, u64::from(onion.port)),
                );
            }
        }
    }
    Ok(())
}
