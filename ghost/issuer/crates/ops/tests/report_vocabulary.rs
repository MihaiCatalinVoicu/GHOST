//! The operator tools print a fixed vocabulary only (design §14.1, §19.17; ADR-26 point 7): every
//! code and field is listed, every word a line can carry comes from a static table, and the lines
//! of real runs, in process and from the binary, have the form `CODE field=value ...`.

mod common;

use std::collections::BTreeSet;
use std::process::Command;

use common::*;
use ghost_entitlement::monero::MoneroNetwork;
use ghost_entitlement::{Kind, ScheduleError};
use ghost_issuer::custody::kind_name;
use ghost_issuer::reconcile::Mismatch;
use ghost_issuer_ops::ledger::Transition;
use ghost_issuer_ops::report::{self, Code, Field, Line};

fn code_index(c: Code) -> usize {
    match c {
        Code::Usage => 0,
        Code::IoError => 1,
        Code::InputRefused => 2,
        Code::CustodySecretCreated => 3,
        Code::ScheduleKeyCreated => 4,
        Code::KeyCreated => 5,
        Code::KeyRefused => 6,
        Code::KeyMissing => 7,
        Code::KeyConflict => 8,
        Code::SealKeyReady => 9,
        Code::SealLoadWritten => 10,
        Code::SealRefused => 11,
        Code::EsSigned => 12,
        Code::EsOk => 13,
        Code::EsRefused => 14,
        Code::EsAppendOnly => 15,
        Code::DirectoryOk => 16,
        Code::DirectoryRefused => 17,
        Code::OnionKeyCreated => 18,
        Code::OpsKeyCreated => 19,
        Code::PayoutAccepted => 20,
        Code::PayoutRefused => 21,
        Code::EntryState => 22,
        Code::AckWritten => 23,
        Code::ReconciliationOk => 24,
        Code::ReconciliationMismatch => 25,
        Code::CountersWritten => 26,
        Code::SegmentPruned => 27,
        Code::JournalPruned => 28,
        Code::PruneRefused => 29,
        Code::IssuerOnion => 30,
        Code::SlotOnion => 31,
    }
}

fn field_index(f: Field) -> usize {
    match f {
        Field::Reason => 0,
        Field::Flag => 1,
        Field::File => 2,
        Field::Line => 3,
        Field::Directive => 4,
        Field::Kind => 5,
        Field::Epoch => 6,
        Field::KeyId => 7,
        Field::Public => 8,
        Field::Entries => 9,
        Field::Seq => 10,
        Field::Network => 11,
        Field::FirstWeek => 12,
        Field::LastWeek => 13,
        Field::Weeks => 14,
        Field::Keys => 15,
        Field::Slots => 16,
        Field::Sha256 => 17,
        Field::ScheduleKey => 18,
        Field::PreviousSeq => 19,
        Field::Week => 20,
        Field::Slot => 21,
        Field::History => 22,
        Field::Batch => 23,
        Field::Entry => 24,
        Field::State => 25,
        Field::Total => 26,
        Field::PaidSoFar => 27,
        Field::Incoming => 28,
        Field::Txid => 29,
        Field::Images => 30,
        Field::Relays => 31,
        Field::Refused => 32,
        Field::Counters => 33,
        Field::Removed => 34,
        Field::Kept => 35,
        Field::FirstSeq => 36,
        Field::LastSeq => 37,
        Field::Applied => 38,
        Field::Onion => 39,
        Field::Port => 40,
    }
}

fn is_code_name(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_uppercase())
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn is_field_name(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn is_value(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// A v3 onion host name as Tor writes it: 56 lowercase base32 characters and `.onion`.
fn is_onion_host(s: &str) -> bool {
    s.strip_suffix(".onion").is_some_and(|label| {
        label.len() == 56
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    })
}

/// `CODE field=value ...` with a listed code, listed fields and vocabulary values (an onion host
/// name in the `onion` field only).
fn well_formed(text: &str) -> bool {
    let mut tokens = text.split(' ');
    let code_ok = tokens
        .next()
        .is_some_and(|c| Code::ALL.iter().any(|k| k.name() == c));
    code_ok
        && tokens.all(|t| {
            t.split_once('=').is_some_and(|(name, value)| {
                Field::ALL.iter().any(|f| f.name() == name)
                    && (is_value(value) || (name == "onion" && is_onion_host(value)))
            })
        })
}

#[test]
fn every_code_and_field_is_listed_once_with_a_well_formed_name() {
    for (i, c) in Code::ALL.iter().enumerate() {
        assert_eq!(code_index(*c), i);
        assert!(is_code_name(c.name()), "{}", c.name());
    }
    let names: BTreeSet<&str> = Code::ALL.iter().map(|c| c.name()).collect();
    assert_eq!(names.len(), Code::ALL.len());
    for (i, f) in Field::ALL.iter().enumerate() {
        assert_eq!(field_index(*f), i);
        assert!(is_field_name(f.name()), "{}", f.name());
    }
    let names: BTreeSet<&str> = Field::ALL.iter().map(|f| f.name()).collect();
    assert_eq!(names.len(), Field::ALL.len());
}

#[test]
fn every_static_word_is_in_the_vocabulary() {
    for k in Kind::ALL {
        assert!(is_value(kind_name(k)));
    }
    for n in [
        MoneroNetwork::Mainnet,
        MoneroNetwork::Stagenet,
        MoneroNetwork::Regtest,
    ] {
        assert!(is_value(report::network_name(n)));
    }
    let errors = [
        ScheduleError::Encoding,
        ScheduleError::Network,
        ScheduleError::NoPinnedKey,
        ScheduleError::Signature,
        ScheduleError::IssuerName,
        ScheduleError::Onion,
        ScheduleError::Constants,
        ScheduleError::SlotTable,
        ScheduleError::PriceTable,
        ScheduleError::DuplicateKey,
        ScheduleError::KeyFormat,
        ScheduleError::KeyProof,
        ScheduleError::Coverage,
        ScheduleError::Revocation,
        ScheduleError::Rollback,
        ScheduleError::KeyChanged,
        ScheduleError::SlotSetChanged,
        ScheduleError::PriceChanged,
        ScheduleError::RevocationDropped,
        ScheduleError::RegtestRefused,
    ];
    let words: BTreeSet<&str> = errors.iter().map(|e| report::schedule_error(*e)).collect();
    assert_eq!(words.len(), errors.len());
    assert!(words.iter().all(|w| is_value(w)));
    // Every reconciliation mismatch renders as a well-formed line with a distinct reason.
    let mismatches = [
        Mismatch::SignedAccess { week: 1 },
        Mismatch::SignedInvite { epoch: 1 },
        Mismatch::SignedCredit { epoch: 1 },
        Mismatch::CreditsExceedSigned { epoch: 1 },
        Mismatch::XmrCredited { base_week: 1 },
        Mismatch::DiscountValue,
        Mismatch::PayoutValue,
        Mismatch::RelayRedemptions { week: 1 },
        Mismatch::ViewBelowCredited,
        Mismatch::PayoutCap,
    ];
    let reasons: BTreeSet<String> = mismatches
        .iter()
        .map(|m| {
            let text = report::mismatch_line(m).render();
            assert!(well_formed(&text), "{text}");
            text.split(' ').nth(1).unwrap().to_string()
        })
        .collect();
    assert_eq!(reasons.len(), mismatches.len());
    for t in Transition::ALL {
        assert!(is_value(t.word()));
    }
}

#[test]
fn lines_of_real_runs_are_well_formed() {
    let dir = tempfile::tempdir().unwrap();
    let es = arg(&test_schedule_path());
    let key = schedule_public_hex();
    let custody = arg(&write(dir.path(), "custody.secret", &custody_seed()));
    let sealed = arg(&ops_fixtures().join("sealed"));
    let directory = arg(&write(
        dir.path(),
        "relays.txt",
        directory_text(&[
            ("ghost/test/relay-a", 1),
            ("ghost/test/relay-b", 1),
            ("ghost/test/relay-c", 1),
        ])
        .as_bytes(),
    ));
    let out = arg(&dir.path().join("load.ghkl"));
    let counters = arg(&dir.path().join("counters.txt"));
    let hs = arg(&dir.path().join("hs"));
    let ops_key = arg(&dir.path().join("ops.key"));
    let missing = arg(&dir.path().join("missing"));
    let db = arg(&snapshot(dir.path(), &[]));
    let journal = dir.path().join("journal");
    std::fs::create_dir(&journal).unwrap();
    let journal = arg(&journal);
    let runs: Vec<Vec<&str>> = vec![
        vec![
            "journal-prune",
            "--database",
            &db,
            "--journal",
            &journal,
            "--schedule",
            &es,
            "--schedule-public-key",
            &key,
            "--now",
            RECONCILE_NOW,
        ],
        vec![
            "journal-prune",
            "--database",
            &db,
            "--journal",
            &missing,
            "--schedule",
            &es,
            "--schedule-public-key",
            &key,
            "--now",
            RECONCILE_NOW,
        ],
        vec![
            "schedule-onions",
            "--schedule",
            &es,
            "--schedule-public-key",
            &key,
            "--now",
            "1790557200",
        ],
        vec!["keygen", "--new-ops-key", &ops_key],
        vec!["payout-check", "--batch", &missing],
        vec!["payout-entry", "--ledger", &missing, "--to", "sideways"],
        vec![
            "payout-ack",
            "--ledger",
            &missing,
            "--batch",
            &missing,
            "--ops-public-key",
            &key,
            "--out",
            &missing,
        ],
        vec![
            "reconcile-check",
            "--database",
            &missing,
            "--schedule",
            &es,
            "--schedule-public-key",
            &key,
            "--now",
            "1790557200",
        ],
        vec![
            "counters-export",
            "--database",
            &missing,
            "--out",
            &counters,
        ],
        vec!["onion-keygen", "--hs-dir", &hs],
        vec!["onion-keygen", "--hs-dir", &hs],
        vec![],
        vec!["nothing"],
        vec!["keygen", "--kind", "access"],
        vec!["schedule-verify", "--schedule", &es],
        vec![
            "schedule-verify",
            "--schedule",
            &es,
            "--schedule-public-key",
            &key,
            "--previous",
            &es,
        ],
        vec![
            "schedule-verify",
            "--schedule",
            &es,
            "--schedule-public-key",
            &key,
            "--relay-directory",
            &directory,
            "--now",
            "1790557200",
        ],
        vec![
            "keys-seal",
            "--schedule",
            &es,
            "--schedule-public-key",
            &key,
            "--custody-secret",
            &custody,
            "--sealed-dir",
            &sealed,
            "--from-week",
            "2960",
            "--through-week",
            "2960",
            "--out",
            &out,
        ],
        vec![
            "keys-seal",
            "--schedule",
            &es,
            "--schedule-public-key",
            &key,
            "--custody-secret",
            &custody,
            "--sealed-dir",
            &sealed,
            "--from-week",
            "2960",
            "--through-week",
            "2960",
            "--out",
            &out,
        ],
    ];
    let mut codes = BTreeSet::new();
    for args in runs {
        let (_, lines) = run(&args);
        assert!(!lines.is_empty(), "{args:?}");
        for line in lines {
            let text = line.render();
            assert!(well_formed(&text), "{text}");
            codes.insert(line.code.name());
        }
    }
    for expected in [
        "USAGE",
        "ES_OK",
        "ES_REFUSED",
        "ES_APPEND_ONLY",
        "DIRECTORY_REFUSED",
        "SEAL_KEY_READY",
        "SEAL_LOAD_WRITTEN",
        "IO_ERROR",
        "ONION_KEY_CREATED",
        "OPS_KEY_CREATED",
        "INPUT_REFUSED",
        "JOURNAL_PRUNED",
        "PRUNE_REFUSED",
        "ISSUER_ONION",
        "SLOT_ONION",
    ] {
        assert!(codes.contains(expected), "{expected} not exercised");
    }
    assert!(well_formed(
        &Line::new(Code::KeyCreated)
            .kind_epoch(Kind::Credit, 227)
            .hex(Field::KeyId, &[0xab; 32])
            .render()
    ));
}

#[test]
fn the_binary_prints_report_lines_only_and_exits_by_status() {
    let bin = env!("CARGO_BIN_EXE_ghost-issuer-ops");
    let out = Command::new(bin).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert_eq!(
        String::from_utf8(out.stderr).unwrap(),
        "USAGE reason=missing-command\n"
    );

    let es = arg(&test_schedule_path());
    let out = Command::new(bin)
        .args([
            "schedule-verify",
            "--schedule",
            &es,
            "--schedule-public-key",
            &schedule_public_hex(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.starts_with("ES_OK seq=1 network=regtest first_week=2957 last_week=2982 weeks=26 keys=36 slots=4 sha256="), "{stdout}");
    assert!(stdout.lines().all(well_formed));

    let dir = tempfile::tempdir().unwrap();
    let mut tampered = test_schedule_bytes();
    tampered[200] ^= 0x01;
    let tampered = write(dir.path(), "tampered.ghes", &tampered);
    let out = Command::new(bin)
        .args([
            "schedule-verify",
            "--schedule",
            &arg(&tampered),
            "--schedule-public-key",
            &schedule_public_hex(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert_eq!(
        String::from_utf8(out.stderr).unwrap(),
        "ES_REFUSED file=schedule reason=signature\n"
    );
}
