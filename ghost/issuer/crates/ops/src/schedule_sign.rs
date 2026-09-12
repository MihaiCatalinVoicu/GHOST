//! `schedule-sign` (runbook K1, design §3.1): builds the Entitlement Schedule from a source file,
//! takes each listed key from the previous schedule or from its public entry (both, when present,
//! must be identical), signs it with the offline schedule key, and writes it only after it verifies
//! under that key (rules 1-4) and, with `--previous`, is append-only against it (rule 5).

use std::collections::BTreeSet;
use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey};
use ghost_entitlement::schedule::{KeyContent, ScheduleMemory};
use ghost_entitlement::{Kind, Schedule};

use crate::args::Flags;
use crate::input::{input_refused, read, read_secret, read_text};
use crate::report::{schedule_error, Code, Field, Line, Sink};
use crate::schedule_verify::{es_ok_line, es_refused};
use crate::{output, public_entry, source, Failure};

const FLAGS: [&str; 5] = ["source", "schedule-key", "public-dir", "previous", "out"];

pub fn run(argv: &[String], sink: &mut dyn Sink) -> Result<(), Failure> {
    let flags = Flags::parse(argv, &FLAGS)?;
    let out = flags.path("out")?;
    let text = read_text(&flags.path("source")?, "source")?;
    let source = source::parse(&text).map_err(|e| {
        Failure::refused(
            input_refused("source", e.reason)
                .num(Field::Line, e.line)
                .word(Field::Directive, e.directive),
        )
    })?;
    let mut seed = read_secret(&flags.path("schedule-key")?, "schedule-key")?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    let schedule_key = signing_key.verifying_key().to_bytes();

    let previous = match flags.opt_path("previous") {
        Some(path) => Some(
            Schedule::verify_with_key(&read(&path, "previous")?, &schedule_key)
                .map_err(|e| es_refused("previous", e))?,
        ),
        None => None,
    };
    let public_dir = flags.opt_path("public-dir");

    let mut content = source.content;
    let mut listed = BTreeSet::new();
    for &(kind, first, last) in &source.key_ranges {
        for epoch in first..=last {
            if !listed.insert((kind, epoch)) {
                return Err(Failure::refused(
                    Line::new(Code::KeyConflict)
                        .kind_epoch(kind, epoch)
                        .word(Field::Reason, "listed-twice"),
                ));
            }
            content.keys.push(key_material(
                kind,
                epoch,
                previous.as_ref(),
                public_dir.as_deref(),
            )?);
        }
    }

    let message = content
        .signing_message()
        .map_err(|e| es_refused("schedule", e))?;
    let signature = signing_key.sign(&message).to_bytes();
    let bytes = content
        .to_signed_bytes(&signature)
        .map_err(|e| es_refused("schedule", e))?;
    let schedule =
        Schedule::verify_with_key(&bytes, &schedule_key).map_err(|e| es_refused("schedule", e))?;
    if let Some(previous) = &previous {
        append_only(&schedule, previous)?;
    }
    output::write_schedule(&out, &bytes, "out")?;
    sink.emit(es_ok_line(Code::EsSigned, &schedule).hex(Field::ScheduleKey, &schedule_key));
    Ok(())
}

/// Rule 5 of `schedule` against `previous` (same network, keys, slot sets, prices, revocations,
/// seq not backwards).
pub(crate) fn append_only(schedule: &Schedule, previous: &Schedule) -> Result<(), Failure> {
    if schedule.network() != previous.network() {
        return Err(Failure::refused(
            Line::new(Code::EsRefused)
                .word(Field::File, "schedule")
                .word(Field::Reason, "network-changed"),
        ));
    }
    let mut memory = ScheduleMemory::default();
    previous.remember(&mut memory);
    schedule.check_memory(&memory).map_err(|e| {
        Failure::refused(
            Line::new(Code::EsRefused)
                .word(Field::File, "schedule")
                .word(Field::Reason, schedule_error(e))
                .num(Field::PreviousSeq, previous.seq()),
        )
    })
}

fn key_material(
    kind: Kind,
    epoch: u64,
    previous: Option<&Schedule>,
    public_dir: Option<&Path>,
) -> Result<KeyContent, Failure> {
    let from_previous = previous.and_then(|p| {
        p.content()
            .keys
            .iter()
            .find(|k| k.kind == kind && k.epoch == epoch)
            .cloned()
    });
    let from_dir = match public_dir {
        Some(dir) => {
            let path = dir.join(public_entry::file_name(kind, epoch));
            if path.exists() {
                let text = read_text(&path, "public-dir")?;
                let entry = public_entry::parse(&text).map_err(|reason| {
                    Failure::refused(input_refused("public-dir", reason).kind_epoch(kind, epoch))
                })?;
                if entry.kind != kind || entry.epoch != epoch {
                    return Err(Failure::refused(
                        input_refused("public-dir", "name-mismatch").kind_epoch(kind, epoch),
                    ));
                }
                Some(entry)
            } else {
                None
            }
        }
        None => None,
    };
    match (from_previous, from_dir) {
        (Some(a), Some(b)) if a != b => Err(Failure::refused(
            Line::new(Code::KeyConflict)
                .kind_epoch(kind, epoch)
                .word(Field::Reason, "previous-differs"),
        )),
        (Some(a), _) => Ok(a),
        (None, Some(b)) => Ok(b),
        (None, None) => Err(Failure::refused(
            Line::new(Code::KeyMissing).kind_epoch(kind, epoch),
        )),
    }
}
