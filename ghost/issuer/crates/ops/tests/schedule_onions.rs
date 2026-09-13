//! `schedule-onions` (design §3.1 rule 4, §19.21 point 1; runbooks "Instalare" and O1): the onions
//! a verified schedule names, in the report vocabulary. The install check of the runbook greps the
//! command's output for the exact `ISSUER_ONION` line of the host name Tor wrote: it matches the
//! schedule's `issuer_onion` once and never a relay's onion (the former search of the schedule's
//! bytes for `<onion>:443` matched both).

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

use common::*;
use ghost_entitlement::grid::week_start;
use ghost_entitlement::onion::{hostname, Onion};
use ghost_entitlement::Schedule;
use ghost_issuer_ops::report::{Code, Field, Line};
use ghost_issuer_ops::Status;

fn protocol_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../protocol/entitlement")
}

fn committed_path() -> PathBuf {
    protocol_dir().join("schedule.ghes")
}

fn committed() -> Schedule {
    Schedule::verify(&std::fs::read(committed_path()).unwrap()).unwrap()
}

fn host_of(onion_text: &str) -> String {
    hostname(&Onion::parse(onion_text).unwrap().pubkey)
}

/// The command's stdout from the binary, as the runbook pipes it.
fn stdout(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_ghost-issuer-ops"))
        .args(args)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{args:?}");
    assert!(out.stderr.is_empty(), "{args:?}");
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn the_issuer_onion_of_the_committed_schedule() {
    let schedule = committed();
    let es = arg(&committed_path());
    let text = stdout(&["schedule-onions", "--schedule", &es]);
    let issuer = Onion::parse(&schedule.content().issuer_onion).unwrap();
    assert_eq!(
        text,
        format!(
            "ISSUER_ONION onion={} port={}\n",
            hostname(&issuer.pubkey),
            issuer.port
        )
    );
    assert_eq!(issuer.port, 443);
}

/// With `--now`: the slot onions of the current and the next week, each the schedule's own entry
/// and each in the committed relay directory (the onion a relay's start-up check compares).
#[test]
fn the_slot_onions_of_the_current_and_the_next_week() {
    let schedule = committed();
    let es = arg(&committed_path());
    let directory = std::fs::read_to_string(protocol_dir().join("relay-directory.txt")).unwrap();
    let w = schedule.first_access_week() + 3;
    let now = (week_start(w) + 3_600).to_string();
    let (status, lines) = run(&["schedule-onions", "--schedule", &es, "--now", &now]);
    assert_eq!(status, Status::Ok);
    assert_eq!(lines[0].code, Code::IssuerOnion);
    let mut seen = BTreeSet::new();
    for line in &lines[1..] {
        assert_eq!(line.code, Code::SlotOnion);
        let (lw, slot) = (
            num(line, Field::Week).unwrap(),
            num(line, Field::Slot).unwrap() as u8,
        );
        assert!(lw == w || lw == w + 1, "{}", line.render());
        let listed = schedule.slot_onion(slot, lw).unwrap();
        let onion = Onion::parse(listed).unwrap();
        assert_eq!(
            line.render(),
            format!(
                "SLOT_ONION week={lw} slot={slot} onion={} port={}",
                hostname(&onion.pubkey),
                onion.port
            )
        );
        assert!(directory.contains(&format!("relay {listed} ")), "{listed}");
        assert!(seen.insert((lw, slot)));
    }
    let expected: usize = [w, w + 1]
        .iter()
        .map(|x| schedule.slots_in_week(*x).len())
        .sum();
    assert_eq!(seen.len(), expected);
    assert!(expected >= 6, "three slots a week");
    // The lines follow the slot table, which may reach past the key horizon: one per listed slot.
    let past = schedule.last_access_week() + 1;
    let after = (week_start(past) + 60).to_string();
    let (_, lines) = run(&["schedule-onions", "--schedule", &es, "--now", &after]);
    let listed = schedule.slots_in_week(past).len() + schedule.slots_in_week(past + 1).len();
    assert_eq!(lines.len(), 1 + listed);
}

/// The runbook's install check (section 2): the grep pattern with the host name Tor wrote finds the
/// `ISSUER_ONION` line exactly once, and the host name of a relay's onion (listed in the same
/// schedule, with the same port 443) finds nothing.
#[test]
fn the_runbook_install_check_matches_the_issuer_onion_only() {
    let runbook = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../infra/issuer/RUNBOOK.md"),
    )
    .unwrap();
    let start = "grep -c -x -F \"";
    let at = runbook
        .find(start)
        .expect("the install check greps the output");
    let line = runbook[at + start.len()..].lines().next().unwrap();
    let pattern = line.strip_suffix('"').expect("one quoted pattern");
    let tor_hostname = "$(cat \"$H/tor/ghost-issuer/hostname\")";
    assert!(pattern.contains(tor_hostname), "{pattern}");
    assert!(runbook[..at].contains("schedule-onions --schedule /etc/ghost/schedule.ghes"));

    let schedule = committed();
    let es = arg(&committed_path());
    let now = (week_start(schedule.first_access_week()) + 60).to_string();
    let output = stdout(&["schedule-onions", "--schedule", &es, "--now", &now]);
    let count = |host: &str| {
        let wanted = pattern.replace(tor_hostname, host);
        output.lines().filter(|l| *l == wanted).count()
    };
    assert_eq!(count(&host_of(&schedule.content().issuer_onion)), 1);
    let w = schedule.first_access_week();
    for slot in schedule.slots_in_week(w) {
        let relay = schedule.slot_onion(slot, w).unwrap();
        assert!(relay.ends_with(":443"), "{relay}");
        assert_eq!(count(&host_of(relay)), 0, "{relay}");
    }
}

#[test]
fn a_schedule_that_does_not_verify_prints_no_onion() {
    let dir = tempfile::tempdir().unwrap();
    let key = schedule_public_hex();
    let es = arg(&test_schedule_path());
    let (status, lines) = run(&["schedule-onions", "--schedule", &es]);
    // The test schedule is not signed by a pinned key.
    assert_eq!(status, Status::Refused);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].code, Code::EsRefused);
    let (status, lines) = run(&[
        "schedule-onions",
        "--schedule",
        &es,
        "--schedule-public-key",
        &key,
    ]);
    assert_eq!(status, Status::Ok);
    assert_eq!(lines.len(), 1);
    let mut tampered = test_schedule_bytes();
    tampered[200] ^= 1;
    let tampered = arg(&write(dir.path(), "tampered.ghes", &tampered));
    let r = run(&[
        "schedule-onions",
        "--schedule",
        &tampered,
        "--schedule-public-key",
        &key,
    ]);
    assert_refused(&r, Code::EsRefused, "signature");
    assert_eq!(r.1.len(), 1);
    let r = run(&["schedule-onions", "--schedule", &es, "--now", "yesterday"]);
    assert_refused(&r, Code::Usage, "bad-value");
    let rendered: Vec<String> = r.1.iter().map(Line::render).collect();
    assert_eq!(rendered, vec!["USAGE reason=bad-value flag=now"]);
}
