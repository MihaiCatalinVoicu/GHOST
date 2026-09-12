//! The committed Entitlement Schedule of slice S2b and its relay directory
//! (`protocol/entitlement/`), checked as `entitlement-schedule.sh` checks them but at fixed
//! instants over the whole horizon instead of the build date (design §19.12 point 2, §19.20
//! point 4).

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::*;
use ghost_entitlement::grid::week_start;
use ghost_entitlement::onion::Onion;
use ghost_entitlement::Schedule;
use ghost_issuer_ops::directory::Directory;
use ghost_issuer_ops::report::Code;
use ghost_issuer_ops::report::Field;
use ghost_issuer_ops::Status;

fn protocol_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../protocol/entitlement")
}

fn committed() -> Schedule {
    Schedule::verify(&std::fs::read(protocol_dir().join("schedule.ghes")).unwrap()).unwrap()
}

fn directory_text() -> String {
    std::fs::read_to_string(protocol_dir().join("relay-directory.txt")).unwrap()
}

/// The date (YYYY-MM-DD, proleptic Gregorian) of the day `days` after 1970-01-01 (H. Hinnant's
/// `civil_from_days`).
fn civil_date(days: u64) -> String {
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// The Monday that starts access week `week`.
fn monday(week: u64) -> String {
    civil_date(week_start(week) / 86_400)
}

#[test]
fn the_readme_deadlines_follow_from_the_committed_horizon() {
    assert_eq!(monday(2957), "2026-09-07");
    let schedule = committed();
    let (first, last) = (schedule.first_access_week(), schedule.last_access_week());
    let readme = std::fs::read_to_string(protocol_dir().join("README.md")).unwrap();
    let wanted = [
        format!("access weeks {first}..{last}"),
        // §3.1: a release ships >= 26 weeks of keys, so week last - 25 is the last release week
        // that may embed this schedule.
        format!("ships by week {} (Monday {})", last - 25, monday(last - 25)),
        // Runbook K2: the next version reaches a release 8 weeks before the first week this one
        // does not cover.
        format!("by week {} (Monday {})", last + 1 - 8, monday(last + 1 - 8)),
    ];
    for text in wanted {
        assert!(readme.contains(&text), "README.md lacks: {text}");
    }
    // Every "week N (Monday D)" of the README names the Monday of week N.
    for (at, _) in readme.match_indices("week ") {
        let rest = &readme[at + 5..];
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        let Some(date) = rest[digits.len()..].strip_prefix(" (Monday ") else {
            continue;
        };
        let week: u64 = digits.parse().unwrap();
        assert_eq!(&date[..10], monday(week), "week {week}");
    }
}

#[test]
fn schedule_verify_accepts_the_committed_schedule_under_the_pinned_key() {
    let es = arg(&protocol_dir().join("schedule.ghes"));
    let dir = arg(&protocol_dir().join("relay-directory.txt"));
    // Monday 2026-09-07 01:00 UTC: the first week and the next are checked.
    let now = (week_start(2957) + 3_600).to_string();
    let (status, lines) = run(&[
        "schedule-verify",
        "--schedule",
        &es,
        "--relay-directory",
        &dir,
        "--now",
        &now,
    ]);
    assert_eq!(status, Status::Ok, "{lines:?}");
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0].code, Code::EsOk);
    assert_eq!(word(&lines[0], Field::Network), Some("stagenet"));
    assert_eq!(word(&lines[0], Field::ScheduleKey), Some("pinned"));
    assert_eq!(num(&lines[0], Field::FirstWeek), Some(2957));
    assert_eq!(lines[1].code, Code::DirectoryOk);
    assert_eq!(num(&lines[1], Field::Weeks), Some(2));
}

#[test]
fn every_week_of_the_horizon_passes_the_relay_directory_check() {
    let schedule = committed();
    let directory = Directory::parse(&directory_text()).unwrap();
    let (first, last) = (schedule.first_access_week(), schedule.last_access_week());
    for week in first - 1..=last + 1 {
        let expected = if week < first || week == last {
            1
        } else if week > last {
            0
        } else {
            2
        };
        assert_eq!(
            directory.check(&schedule, week_start(week) + 3_600),
            Ok(expected),
            "week {week}"
        );
    }
}

#[test]
fn the_directory_lists_exactly_the_slot_relays_under_three_operator_ids() {
    let schedule = committed();
    let text = directory_text();
    let entries: Vec<(&str, &str)> = text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            assert_eq!(f.len(), 3, "{l}");
            (f[1], f[2])
        })
        .collect();
    let onions: BTreeSet<&str> = entries.iter().map(|(o, _)| *o).collect();
    let slot_onions: BTreeSet<&str> = schedule
        .content()
        .slots
        .iter()
        .map(|s| s.onion.as_str())
        .collect();
    assert_eq!(onions, slot_onions);
    let operators: BTreeSet<&str> = entries.iter().map(|(_, id)| *id).collect();
    assert_eq!(operators.len(), 3);
    assert!(!onions.contains(schedule.content().issuer_onion.as_str()));
    // Every onion listens on the relay torrc's onion port.
    for onion in onions {
        assert_eq!(Onion::parse(onion).unwrap().port, 443);
    }
    assert_eq!(
        Onion::parse(&schedule.content().issuer_onion).unwrap().port,
        443
    );
}
