//! `schedule-sign` and `schedule-verify` (design §3.1, §14.1, §19.2, §19.12) on the committed test
//! schedule and edits of it.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use ghost_entitlement::grid::week_start;
use ghost_entitlement::monero::MoneroNetwork;
use ghost_entitlement::schedule::SlotEntry;
use ghost_entitlement::Kind;
use ghost_issuer_ops::report::{Code, Field, Line, Value};
use ghost_issuer_ops::{public_entry, source, Status};

fn source_text() -> String {
    std::fs::read_to_string(ops_fixtures().join("test_schedule.source")).unwrap()
}

/// The source of the test schedule with `edit` applied to each line (None keeps the line).
fn edited_source(edit: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::new();
    for line in source_text().lines() {
        out.push_str(&edit(line).unwrap_or_else(|| line.to_string()));
        out.push('\n');
    }
    out
}

fn with_seq(seq: u64) -> impl Fn(&str) -> Option<String> {
    move |line: &str| line.starts_with("seq ").then(|| format!("seq {seq}"))
}

/// The test schedule's public entries in `dir`.
fn write_public_entries(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    for k in &test_content().keys {
        write(
            dir,
            &public_entry::file_name(k.kind, k.epoch),
            public_entry::encode(k).as_bytes(),
        );
    }
}

/// Runs `schedule-sign` in `dir` with the test schedule key (unless `dir` already holds one).
fn sign(dir: &Path, source: &str, extra: &[&str]) -> ((Status, Vec<Line>), PathBuf) {
    let source = write(dir, "schedule.source", source.as_bytes());
    let key = dir.join("schedule.key");
    if !key.exists() {
        write(dir, "schedule.key", &schedule_seed());
    }
    let out = dir.join("out.ghes");
    let mut args = vec![
        "schedule-sign".to_string(),
        "--source".into(),
        arg(&source),
        "--schedule-key".into(),
        arg(&key),
        "--out".into(),
        arg(&out),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    (run(&refs), out)
}

fn verify(args: &[&str]) -> (Status, Vec<Line>) {
    let mut all = vec!["schedule-verify"];
    all.extend_from_slice(args);
    run(&all)
}

#[test]
fn sign_reproduces_the_committed_test_schedule() {
    let dir = tempfile::tempdir().unwrap();
    let public = dir.path().join("public");
    write_public_entries(&public);
    let ((status, lines), out) = sign(dir.path(), &source_text(), &["--public-dir", &arg(&public)]);
    assert_eq!(status, Status::Ok, "{lines:?}");
    // Ed25519 is deterministic: the same content and key give the same bytes.
    assert_eq!(std::fs::read(&out).unwrap(), test_schedule_bytes());
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].code, Code::EsSigned);
    assert_eq!(num(&lines[0], Field::Seq), Some(1));
    assert_eq!(word(&lines[0], Field::Network), Some("regtest"));
    assert_eq!(num(&lines[0], Field::Weeks), Some(26));
    assert_eq!(num(&lines[0], Field::Keys), Some(36));
    assert_eq!(
        field(&lines[0], Field::ScheduleKey),
        Some(&Value::Hex(schedule_public().to_vec()))
    );
}

#[test]
fn sign_takes_keys_from_the_previous_schedule_and_keeps_rule_5() {
    let previous = arg(&test_schedule_path());
    // A valid successor: seq 2, a new slot from the first uncovered week on.
    let relay_e = onion("ghost/test/relay-e", 443);
    let successor = format!(
        "{}slot 3 {relay_e} {} 0\n",
        edited_source(with_seq(2)),
        LAST_WEEK + 1
    );
    let dir = tempfile::tempdir().unwrap();
    let ((status, lines), out) = sign(dir.path(), &successor, &["--previous", &previous]);
    assert_eq!(status, Status::Ok, "{lines:?}");
    let mut expected = test_content();
    expected.seq = 2;
    expected.slots.push(SlotEntry {
        slot: 3,
        onion: relay_e.clone(),
        valid_from_week: LAST_WEEK + 1,
        valid_until_week: 0,
    });
    assert_eq!(std::fs::read(&out).unwrap(), resign(&expected));

    // The same slot from a covered week changes that week's slot set.
    let changed = format!("{}slot 3 {relay_e} 2970 0\n", edited_source(with_seq(2)));
    let dir = tempfile::tempdir().unwrap();
    let (result, out) = sign(dir.path(), &changed, &["--previous", &previous]);
    assert_refused(&result, Code::EsRefused, "slot-set-changed");
    assert!(!out.exists(), "a refused schedule is never written");

    let dir = tempfile::tempdir().unwrap();
    let (result, _) = sign(
        dir.path(),
        &edited_source(with_seq(0)),
        &["--previous", &previous],
    );
    assert_refused(&result, Code::EsRefused, "rollback");

    let price = |line: &str| {
        line.starts_with("price 229 ")
            .then(|| "price 229 260000000000".to_string())
    };
    let dir = tempfile::tempdir().unwrap();
    let (result, _) = sign(
        dir.path(),
        &edited_source(price),
        &["--previous", &previous],
    );
    assert_refused(&result, Code::EsRefused, "price-changed");

    let network = |line: &str| {
        line.starts_with("network ")
            .then(|| "network stagenet".into())
    };
    let dir = tempfile::tempdir().unwrap();
    let (result, _) = sign(
        dir.path(),
        &edited_source(network),
        &["--previous", &previous],
    );
    assert_refused(&result, Code::EsRefused, "network-changed");

    // A revocation may be added.
    let revoked = format!("{}revoke access {LAST_WEEK}\n", edited_source(with_seq(2)));
    let dir = tempfile::tempdir().unwrap();
    let ((status, lines), _) = sign(dir.path(), &revoked, &["--previous", &previous]);
    assert_eq!(status, Status::Ok, "{lines:?}");

    // The previous schedule must verify under the signing key.
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "schedule.key", &[7u8; 32]);
    let ((status, lines), _) = sign(dir.path(), &source_text(), &["--previous", &previous]);
    assert_eq!(status, Status::Refused);
    assert_eq!(lines[0].code, Code::EsRefused);
    assert_eq!(word(&lines[0], Field::File), Some("previous"));
    assert_eq!(word(&lines[0], Field::Reason), Some("signature"));
}

#[test]
fn sign_refuses_missing_conflicting_and_misnamed_keys() {
    let previous = arg(&test_schedule_path());

    let dir = tempfile::tempdir().unwrap();
    let ((status, lines), out) = sign(dir.path(), &source_text(), &[]);
    assert_eq!(status, Status::Refused);
    assert_eq!(lines[0].code, Code::KeyMissing);
    assert_eq!(word(&lines[0], Field::Kind), Some("access"));
    assert_eq!(num(&lines[0], Field::Epoch), Some(FIRST_WEEK));
    assert!(!out.exists());

    // A public entry that differs from the previous schedule's key.
    let dir = tempfile::tempdir().unwrap();
    let public = dir.path().join("public");
    write_public_entries(&public);
    let mut other = test_content().keys[1].clone();
    other.epoch = FIRST_WEEK;
    let name = public_entry::file_name(Kind::Access, FIRST_WEEK);
    write(&public, &name, public_entry::encode(&other).as_bytes());
    let (result, _) = sign(
        dir.path(),
        &source_text(),
        &["--previous", &previous, "--public-dir", &arg(&public)],
    );
    assert_refused(&result, Code::KeyConflict, "previous-differs");

    // A file whose entry names another (kind, epoch).
    let dir = tempfile::tempdir().unwrap();
    let public = dir.path().join("public");
    write_public_entries(&public);
    let second = public_entry::encode(&test_content().keys[1]);
    write(&public, &name, second.as_bytes());
    let (result, _) = sign(dir.path(), &source_text(), &["--public-dir", &arg(&public)]);
    assert_refused(&result, Code::InputRefused, "name-mismatch");

    write(&public, &name, b"ghost-es-key-v1 access 2957 00\n");
    let (result, _) = sign(dir.path(), &source_text(), &["--public-dir", &arg(&public)]);
    assert_refused(&result, Code::InputRefused, "format");

    // The same key listed twice.
    let dir = tempfile::tempdir().unwrap();
    let twice = format!("{}keys access {FIRST_WEEK} {FIRST_WEEK}\n", source_text());
    let (result, _) = sign(dir.path(), &twice, &["--previous", &previous]);
    assert_refused(&result, Code::KeyConflict, "listed-twice");

    // 25 access weeks break rule 3; nothing is written.
    let short = |line: &str| {
        line.starts_with("keys access ")
            .then(|| format!("keys access {FIRST_WEEK} {}", LAST_WEEK - 1))
    };
    let dir = tempfile::tempdir().unwrap();
    let (result, out) = sign(
        dir.path(),
        &edited_source(short),
        &["--previous", &previous],
    );
    assert_refused(&result, Code::EsRefused, "coverage");
    assert!(!out.exists());

    // An existing output is never replaced.
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "out.ghes", b"existing");
    let (result, out) = sign(dir.path(), &source_text(), &["--previous", &previous]);
    assert_refused(&result, Code::IoError, "exists");
    assert_eq!(std::fs::read(out).unwrap(), b"existing");
}

#[test]
fn source_parser_reads_the_test_source_and_refuses_malformed_ones() {
    let parsed = source::parse(&source_text()).unwrap();
    assert_eq!(parsed.content.seq, 1);
    assert_eq!(
        parsed.key_ranges,
        [
            (Kind::Access, FIRST_WEEK, LAST_WEEK),
            (Kind::Invite, 739, 745),
            (Kind::Credit, 227, 229)
        ]
    );
    let mut expected = test_content();
    expected.keys.clear();
    assert_eq!(parsed.content, expected);

    let err = |text: &str| source::parse(text).unwrap_err();
    let base = source_text();
    let lines = base.lines().count() as u64;
    let e = err(&format!("{base}seq 3\n"));
    assert_eq!(
        (e.line, e.directive, e.reason),
        (lines + 1, "seq", "duplicate")
    );
    let e = err(&edited_source(|l| {
        l.starts_with("grace_blocks ").then(String::new)
    }));
    assert_eq!(
        (e.line, e.directive, e.reason),
        (0, "grace_blocks", "missing")
    );
    let e = err(&format!("{base}slots 1\n"));
    assert_eq!((e.directive, e.reason), ("line", "unknown-directive"));
    let e = err(&edited_source(|l| {
        l.starts_with("confirmations ")
            .then(|| "confirmations 256".into())
    }));
    assert_eq!((e.directive, e.reason), ("confirmations", "number"));
    let e = err(&edited_source(with_seq_text("01")));
    assert_eq!((e.directive, e.reason), ("seq", "number"));
    assert_eq!(err(&format!("{base}price 1\n")).reason, "arity");
    assert_eq!(err(&format!("{base}keys access 5 4\n")).reason, "range");
    assert_eq!(err(&format!("{base}keys access 0 4096\n")).reason, "range");
    assert_eq!(err(&format!("{base}revoke Access 1\n")).reason, "kind");
    assert_eq!(err(&format!("{base}seq\n")).reason, "arity");
}

fn with_seq_text(text: &'static str) -> impl Fn(&str) -> Option<String> {
    move |line: &str| line.starts_with("seq ").then(|| format!("seq {text}"))
}

#[test]
fn verify_uses_the_pinned_key_unless_one_is_given() {
    let es = arg(&test_schedule_path());
    assert_refused(
        &verify(&["--schedule", &es]),
        Code::EsRefused,
        "no-pinned-key",
    );

    let (status, lines) = verify(&[
        "--schedule",
        &es,
        "--schedule-public-key",
        &schedule_public_hex(),
    ]);
    assert_eq!(status, Status::Ok, "{lines:?}");
    let l = &lines[0];
    assert_eq!(l.code, Code::EsOk);
    assert_eq!(num(l, Field::FirstWeek), Some(FIRST_WEEK));
    assert_eq!(num(l, Field::LastWeek), Some(LAST_WEEK));
    assert_eq!(num(l, Field::Slots), Some(4));
    assert_eq!(
        field(l, Field::Sha256),
        Some(&Value::Hex(test_schedule().digest().to_vec()))
    );

    assert_refused(
        &verify(&["--schedule", &es, "--schedule-public-key", "00"]),
        Code::Usage,
        "bad-value",
    );
    assert_refused(
        &verify(&["--schedule", &es, "--schedule-public-key", &"00".repeat(32)]),
        Code::EsRefused,
        "signature",
    );
}

#[test]
fn verify_checks_rule_5_against_the_previous_schedule() {
    let es = arg(&test_schedule_path());
    let key = schedule_public_hex();
    let (status, lines) = verify(&[
        "--schedule",
        &es,
        "--schedule-public-key",
        &key,
        "--previous",
        &es,
    ]);
    assert_eq!(status, Status::Ok, "{lines:?}");
    assert_eq!(lines[1].code, Code::EsAppendOnly);
    assert_eq!(num(&lines[1], Field::PreviousSeq), Some(1));

    let dir = tempfile::tempdir().unwrap();
    let mut changed = test_content();
    changed.seq = 2;
    changed.slots.push(SlotEntry {
        slot: 3,
        onion: onion("ghost/test/relay-e", 443),
        valid_from_week: 2970,
        valid_until_week: 0,
    });
    let changed = write(dir.path(), "changed.ghes", &resign(&changed));
    let result = verify(&[
        "--schedule",
        &arg(&changed),
        "--schedule-public-key",
        &key,
        "--previous",
        &es,
    ]);
    assert_refused(&result, Code::EsRefused, "slot-set-changed");

    let mut tampered = test_schedule_bytes();
    tampered[200] ^= 0x01;
    let tampered = write(dir.path(), "tampered.ghes", &tampered);
    let (status, lines) = verify(&[
        "--schedule",
        &es,
        "--schedule-public-key",
        &key,
        "--previous",
        &arg(&tampered),
    ]);
    assert_eq!(status, Status::Refused);
    let last = lines.last().unwrap();
    assert_eq!(word(last, Field::File), Some("previous"));
    assert_eq!(word(last, Field::Reason), Some("signature"));
}

/// The test schedule with `seq` and a slot 3 valid from `from_week`.
fn with_slot_3(from_week: u64, seq: u64) -> Vec<u8> {
    let mut c = test_content();
    c.seq = seq;
    c.slots.push(SlotEntry {
        slot: 3,
        onion: onion("ghost/test/relay-e", 443),
        valid_from_week: from_week,
        valid_until_week: 0,
    });
    resign(&c)
}

#[test]
fn verify_checks_rule_5_across_the_whole_history_in_order() {
    let a = arg(&test_schedule_path());
    let key = schedule_public_hex();
    let dir = tempfile::tempdir().unwrap();
    // B (seq 2) changes the slot set of covered week 2970; C (seq 3) is B re-signed.
    let b = arg(&write(dir.path(), "b.ghes", &with_slot_3(2970, 2)));
    let c = arg(&write(dir.path(), "c.ghes", &with_slot_3(2970, 3)));
    let with_history = |schedule: &str, history: &[&str]| {
        let mut args = vec!["--schedule", schedule, "--schedule-public-key", &key];
        for h in history {
            args.extend(["--previous", h]);
        }
        verify(&args)
    };

    // C against B alone holds rule 5; with the whole history the middle version B is refused.
    assert_eq!(with_history(&c, &[&b]).0, Status::Ok);
    let result = with_history(&c, &[&a, &b]);
    assert_refused(&result, Code::EsRefused, "slot-set-changed");
    let last = result.1.last().unwrap();
    assert_eq!(word(last, Field::File), Some("previous"));
    assert_eq!(num(last, Field::Seq), Some(2));
    assert_eq!(num(last, Field::PreviousSeq), Some(1));

    // A valid history: P (seq 2) adds a slot after coverage, P3 (seq 3) re-signs it.
    let p = arg(&write(dir.path(), "p.ghes", &with_slot_3(LAST_WEEK + 1, 2)));
    let p3 = arg(&write(
        dir.path(),
        "p3.ghes",
        &with_slot_3(LAST_WEEK + 1, 3),
    ));
    let (status, lines) = with_history(&p3, &[&a, &p]);
    assert_eq!(status, Status::Ok, "{lines:?}");
    let last = lines.last().unwrap();
    assert_eq!(last.code, Code::EsAppendOnly);
    assert_eq!(num(last, Field::PreviousSeq), Some(2));
    assert_eq!(num(last, Field::History), Some(2));

    // Going back to an earlier version is a rollback against the history.
    let result = with_history(&a, &[&a, &p]);
    assert_refused(&result, Code::EsRefused, "rollback");
    assert_eq!(
        word(result.1.last().unwrap(), Field::File),
        Some("schedule")
    );

    // Every version keeps the network of the first.
    let mut stagenet = test_content();
    stagenet.seq = 2;
    stagenet.network = MoneroNetwork::Stagenet;
    let s = arg(&write(dir.path(), "s.ghes", &resign(&stagenet)));
    let result = with_history(&p3, &[&a, &s]);
    assert_refused(&result, Code::EsRefused, "network-changed");
    assert_eq!(
        word(result.1.last().unwrap(), Field::File),
        Some("previous")
    );

    // Each earlier version verifies under the same key.
    let mut tampered = std::fs::read(&p).unwrap();
    tampered[200] ^= 0x01;
    let t = arg(&write(dir.path(), "t.ghes", &tampered));
    let result = with_history(&p3, &[&a, &t]);
    assert_refused(&result, Code::EsRefused, "signature");
    assert_eq!(
        word(result.1.last().unwrap(), Field::File),
        Some("previous")
    );
}

fn all_relays(operators: [u8; 4]) -> Vec<(&'static str, u8)> {
    [
        "ghost/test/relay-a",
        "ghost/test/relay-b",
        "ghost/test/relay-c",
        "ghost/test/relay-d",
    ]
    .into_iter()
    .zip(operators)
    .collect()
}

#[test]
fn verify_checks_the_relay_directory_for_the_current_and_next_week() {
    let es = arg(&test_schedule_path());
    let key = schedule_public_hex();
    let dir = tempfile::tempdir().unwrap();
    let check = |relays: &[(&str, u8)], now: u64, schedule: &str| {
        let directory = write(dir.path(), "relays.txt", directory_text(relays).as_bytes());
        verify(&[
            "--schedule",
            schedule,
            "--schedule-public-key",
            &key,
            "--relay-directory",
            &arg(&directory),
            "--now",
            &now.to_string(),
        ])
    };
    let in_week = |w: u64| week_start(w) + 3_600;

    let (status, lines) = check(&all_relays([1, 1, 2, 2]), in_week(2960), &es);
    assert_eq!(status, Status::Ok, "{lines:?}");
    assert_eq!(lines[1].code, Code::DirectoryOk);
    assert_eq!(num(&lines[1], Field::Weeks), Some(2));

    let without_c: Vec<_> = all_relays([1, 1, 2, 2])
        .into_iter()
        .filter(|(l, _)| !l.ends_with("relay-c"))
        .collect();
    let result = check(&without_c, in_week(2960), &es);
    assert_refused(&result, Code::DirectoryRefused, "onion-not-in-directory");
    let last = result.1.last().unwrap();
    assert_eq!(num(last, Field::Week), Some(2960));
    assert_eq!(num(last, Field::Slot), Some(2));

    // In week 2966 the next week's slot 2 is relay-d.
    let without_d: Vec<_> = all_relays([1, 1, 2, 2])
        .into_iter()
        .filter(|(l, _)| !l.ends_with("relay-d"))
        .collect();
    assert_eq!(check(&without_d, in_week(2965), &es).0, Status::Ok);
    let result = check(&without_d, in_week(2966), &es);
    assert_refused(&result, Code::DirectoryRefused, "onion-not-in-directory");
    assert_eq!(num(result.1.last().unwrap(), Field::Week), Some(2967));

    let result = check(&all_relays([1, 1, 1, 1]), in_week(2960), &es);
    assert_refused(&result, Code::DirectoryRefused, "single-operator");

    // Only two slots in a week.
    let mut two = test_content();
    two.slots.retain(|s| s.slot != 2);
    let two = write(dir.path(), "two.ghes", &resign(&two));
    let result = check(&all_relays([1, 2, 2, 2]), in_week(2960), &arg(&two));
    assert_refused(&result, Code::DirectoryRefused, "fewer-than-three-slots");

    // Weeks outside the schedule are not checked.
    let (status, lines) = check(&all_relays([1, 1, 1, 1]), in_week(2950), &es);
    assert_eq!(status, Status::Ok);
    assert_eq!(num(&lines[1], Field::Weeks), Some(0));
    let (_, lines) = check(&all_relays([1, 1, 2, 2]), in_week(LAST_WEEK), &es);
    assert_eq!(num(&lines[1], Field::Weeks), Some(1));

    // Malformed directories and flags.
    let bad = write(dir.path(), "bad.txt", b"# c\nrelay x.onion:1 00\n");
    let args = |directory: &PathBuf| {
        verify(&[
            "--schedule",
            &es,
            "--schedule-public-key",
            &key,
            "--relay-directory",
            &arg(directory),
            "--now",
            "0",
        ])
    };
    let result = args(&bad);
    assert_refused(&result, Code::InputRefused, "onion");
    assert_eq!(num(result.1.last().unwrap(), Field::Line), Some(2));
    let a = onion("ghost/test/relay-a", 443);
    let dup = write(
        dir.path(),
        "dup.txt",
        format!("relay {a} {0}\nrelay {a} {0}\n", "01".repeat(16)).as_bytes(),
    );
    assert_refused(&args(&dup), Code::InputRefused, "duplicate");
    let short = write(
        dir.path(),
        "short.txt",
        format!("relay {a} 0101\n").as_bytes(),
    );
    assert_refused(&args(&short), Code::InputRefused, "operator");
    let empty = write(dir.path(), "empty.txt", b"# nothing\n");
    assert_refused(&args(&empty), Code::InputRefused, "empty");
    assert_refused(
        &verify(&["--schedule", &es, "--relay-directory", "x"]),
        Code::Usage,
        "missing-flag",
    );
}
