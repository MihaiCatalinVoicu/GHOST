//! `keys-seal` (runbook K3, design §3.3, §19.1): the key load file for the issuer. For access weeks
//! `[from-week, through-week]` it lists the `k_seal` of every ACCESS week, of every INVITE and
//! CREDIT epoch those weeks touch, and of the CREDIT epoch before them when the schedule has it
//! (kept for `RefreshCredit`, §19.1 rule 1). Revoked epochs stay listed: the issuer keeps signing
//! their layout positions until the next epoch (runbook I1). Each `k_seal` is proven, before the
//! file is written, to open its sealed file into exactly the key its schedule entry names.

use std::collections::BTreeSet;

use ghost_entitlement::grid::{credit_epoch, invite_epoch};
use ghost_entitlement::Kind;
use ghost_issuer::custody::{self, CustodyError, CustodySecret, SealLoad};
use ghost_issuer::signer::CheckedSigner;

use crate::args::Flags;
use crate::input::{io_error, read, read_secret};
use crate::report::{Code, Field, Line, Sink};
use crate::schedule_verify::load_schedule;
use crate::{output, Failure};

/// At most this many access weeks per load (the K3 window spans 13).
pub const MAX_WEEKS: u64 = 64;

const FLAGS: [&str; 7] = [
    "schedule",
    "schedule-public-key",
    "custody-secret",
    "sealed-dir",
    "from-week",
    "through-week",
    "out",
];

fn seal_refused(kind: Kind, epoch: u64, reason: &'static str) -> Failure {
    Failure::refused(
        Line::new(Code::SealRefused)
            .kind_epoch(kind, epoch)
            .word(Field::Reason, reason),
    )
}

pub fn run(argv: &[String], sink: &mut dyn Sink) -> Result<(), Failure> {
    let flags = Flags::parse(argv, &FLAGS)?;
    let from = flags.u64("from-week")?;
    let through = flags.u64("through-week")?;
    if through < from || through - from >= MAX_WEEKS {
        return Err(Failure::usage("bad-value", Some("through-week")));
    }
    let out = flags.path("out")?;
    let sealed_dir = flags.path("sealed-dir")?;
    let schedule = load_schedule(&flags, "schedule")?;
    let secret = CustodySecret::from_bytes(read_secret(
        &flags.path("custody-secret")?,
        "custody-secret",
    )?);

    let mut needed = BTreeSet::new();
    for week in from..=through {
        needed.insert((Kind::Access, week));
        needed.insert((Kind::Invite, invite_epoch(week)));
        needed.insert((Kind::Credit, credit_epoch(week)));
    }
    let refresh = credit_epoch(from)
        .checked_sub(1)
        .filter(|&c| schedule.key(Kind::Credit, c).is_some());

    let mut load = SealLoad::new();
    for (kind, epoch) in needed.into_iter().chain(refresh.map(|c| (Kind::Credit, c))) {
        let entry = schedule.key(kind, epoch).ok_or(Failure::refused(
            Line::new(Code::KeyMissing).kind_epoch(kind, epoch),
        ))?;
        let sealed = read(
            &sealed_dir.join(custody::sealed_file_name(kind, epoch)),
            "sealed-dir",
        )
        .map_err(|mut f| {
            f.line = f.line.kind_epoch(kind, epoch);
            f
        })?;
        let seal_key = secret.seal_key(kind, epoch);
        let signer = custody::unseal(&seal_key, kind, epoch, &sealed).map_err(|e| {
            seal_refused(
                kind,
                epoch,
                match e {
                    CustodyError::Format => "format",
                    CustodyError::WrongKey => "wrong-key",
                    CustodyError::Open => "open",
                    CustodyError::Random => "random",
                    CustodyError::Key(_) => "key",
                },
            )
        })?;
        // The unsealed key must be the schedule's key, proven by one checked signature.
        CheckedSigner::new(signer, entry.public_key.clone())
            .map_err(|_| seal_refused(kind, epoch, "mismatch"))?;
        load.insert(kind, epoch, seal_key)
            .map_err(|_| seal_refused(kind, epoch, "duplicate"))?;
        sink.emit(
            Line::new(Code::SealKeyReady)
                .kind_epoch(kind, epoch)
                .hex(Field::KeyId, &entry.key_id),
        );
    }
    // The encoded load is plaintext key material: write_seal_load wipes it on every path.
    let mut bytes = load.encode().map_err(|_| io_error("out", "encode"))?;
    output::write_seal_load(&out, &mut bytes, "out")?;
    sink.emit(Line::new(Code::SealLoadWritten).num(Field::Entries, load.len() as u64));
    Ok(())
}
