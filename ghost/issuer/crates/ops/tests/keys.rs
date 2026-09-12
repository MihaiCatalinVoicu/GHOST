//! `keygen` (runbook K1) and `keys-seal` (runbook K3), design §3.3, §19.1.

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use common::*;
use ed25519_dalek::SigningKey;
use ghost_blind_rsa::PublicKey;
use ghost_entitlement::{token, Kind};
use ghost_issuer::custody::{self, CustodySecret, SealLoad};
use ghost_issuer::signer::CheckedSigner;
use ghost_issuer_ops::report::{Code, Field, Line, Value};
use ghost_issuer_ops::{public_entry, Status};
use ring::rand::SystemRandom;

fn custody_file(dir: &Path) -> PathBuf {
    write(dir, "custody.secret", &custody_seed())
}

#[test]
fn keygen_creates_checked_sealed_keys_with_their_public_entries() {
    let dir = tempfile::tempdir().unwrap();
    let custody = arg(&custody_file(dir.path()));
    let public = dir.path().join("public");
    let sealed = dir.path().join("sealed");
    let args = [
        "keygen",
        "--kind",
        "invite",
        "--from-epoch",
        "5000",
        "--count",
        "2",
        "--custody-secret",
        &custody,
        "--public-dir",
        &arg(&public),
        "--sealed-dir",
        &arg(&sealed),
    ];
    let (status, lines) = run(&args);
    assert_eq!(status, Status::Ok, "{lines:?}");
    assert_eq!(lines.len(), 2);
    let secret = CustodySecret::from_bytes(custody_seed());
    let mut moduli = BTreeSet::new();
    for (line, epoch) in lines.iter().zip(5000u64..) {
        assert_eq!(line.code, Code::KeyCreated);
        assert_eq!(word(line, Field::Kind), Some("invite"));
        assert_eq!(num(line, Field::Epoch), Some(epoch));
        let text =
            std::fs::read_to_string(public.join(public_entry::file_name(Kind::Invite, epoch)))
                .unwrap();
        let entry = public_entry::parse(&text).unwrap();
        assert_eq!((entry.kind, entry.epoch), (Kind::Invite, epoch));
        let pk = PublicKey::from_spki(&entry.spki).unwrap();
        token::check_key(&pk).unwrap();
        ghost_blind_rsa::verify_permutation_proof(&pk, &entry.proof).unwrap();
        assert_eq!(
            field(line, Field::KeyId),
            Some(&Value::Hex(token::key_id(&entry.spki).to_vec()))
        );
        let bytes =
            std::fs::read(sealed.join(custody::sealed_file_name(Kind::Invite, epoch))).unwrap();
        let signer = custody::unseal(
            &secret.seal_key(Kind::Invite, epoch),
            Kind::Invite,
            epoch,
            &bytes,
        )
        .unwrap();
        assert_eq!(signer.public_key(), &pk);
        assert_eq!(signer.check_prime_conditions(), Ok(()));
        assert!(CheckedSigner::new(signer, pk.clone()).is_ok());
        moduli.insert(pk.n_bytes().to_vec());
    }
    assert_eq!(moduli.len(), 2);

    // A key is never replaced.
    let result = run(&args);
    assert_refused(&result, Code::IoError, "exists");
    let last = result.1.last().unwrap();
    assert_eq!(word(last, Field::Flag), Some("public-dir"));
    assert_eq!(num(last, Field::Epoch), Some(5000));
}

#[test]
fn keygen_writes_new_secrets_only() {
    let dir = tempfile::tempdir().unwrap();
    let custody = dir.path().join("custody.secret");
    let (status, lines) = run(&["keygen", "--new-custody-secret", &arg(&custody)]);
    assert_eq!(status, Status::Ok);
    assert_eq!(lines, [Line::new(Code::CustodySecretCreated)]);
    let first = std::fs::read(&custody).unwrap();
    assert_eq!(first.len(), 32);
    assert_refused(
        &run(&["keygen", "--new-custody-secret", &arg(&custody)]),
        Code::IoError,
        "exists",
    );
    assert_eq!(std::fs::read(&custody).unwrap(), first);

    let key = dir.path().join("schedule.key");
    let (status, lines) = run(&["keygen", "--new-schedule-key", &arg(&key)]);
    assert_eq!(status, Status::Ok);
    let seed: [u8; 32] = std::fs::read(&key).unwrap().try_into().unwrap();
    assert_eq!(lines[0].code, Code::ScheduleKeyCreated);
    assert_eq!(
        field(&lines[0], Field::Public),
        Some(&Value::Hex(
            SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes()
                .to_vec()
        ))
    );
    let result = run(&["keygen", "--new-schedule-key", "x", "--kind", "access"]);
    assert_refused(&result, Code::Usage, "conflicting-flags");
    assert_eq!(result.0, Status::Usage);
}

#[test]
fn command_lines_are_refused_by_flag_name() {
    let dir = tempfile::tempdir().unwrap();
    let short = arg(&write(dir.path(), "short.secret", &[1u8; 31]));
    let keygen = |kind: &str, from: &str, count: &str, custody: &str| {
        run(&[
            "keygen",
            "--kind",
            kind,
            "--from-epoch",
            from,
            "--count",
            count,
            "--custody-secret",
            custody,
            "--public-dir",
            "p",
            "--sealed-dir",
            "s",
        ])
    };
    let usage = |r: (Status, Vec<Line>), reason: &str, flag: Option<&str>| {
        assert_eq!(r.0, Status::Usage, "{:?}", r.1);
        assert_refused(&r, Code::Usage, reason);
        assert_eq!(word(r.1.last().unwrap(), Field::Flag), flag);
    };
    usage(keygen("access", "1", "0", "c"), "bad-value", Some("count"));
    usage(
        keygen("access", "1", "105", "c"),
        "bad-value",
        Some("count"),
    );
    usage(keygen("Access", "1", "1", "c"), "bad-value", Some("kind"));
    usage(
        keygen("access", "01", "1", "c"),
        "bad-value",
        Some("from-epoch"),
    );
    usage(
        keygen("access", &u64::MAX.to_string(), "2", "c"),
        "bad-value",
        Some("from-epoch"),
    );
    assert_refused(
        &keygen("access", "1", "1", &short),
        Code::InputRefused,
        "length",
    );
    assert_refused(
        &keygen("access", "1", "1", &arg(&dir.path().join("absent"))),
        Code::IoError,
        "read",
    );
    usage(run(&["keygen", "--color", "x"]), "unknown-flag", None);
    usage(
        run(&["keygen", "--kind", "access", "--kind", "invite"]),
        "repeated-flag",
        Some("kind"),
    );
    usage(run(&["keygen", "--kind"]), "missing-value", Some("kind"));
    usage(
        run(&["keygen", "--kind", "--count"]),
        "missing-value",
        Some("kind"),
    );
    usage(run(&["keygen", "access"]), "unexpected-argument", None);
    usage(run(&[]), "missing-command", None);
    usage(run(&["sign"]), "unknown-command", None);
    usage(run(&["keys-seal"]), "missing-flag", Some("from-week"));
}

fn copy_sealed(to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(ops_fixtures().join("sealed")).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
}

fn keys_seal(
    dir: &Path,
    sealed: &Path,
    from: u64,
    through: u64,
    custody: &Path,
    pinned: bool,
) -> ((Status, Vec<Line>), PathBuf) {
    let out = dir.join("load.ghkl");
    let (from, through) = (from.to_string(), through.to_string());
    let es = arg(&test_schedule_path());
    let key = schedule_public_hex();
    let mut args = vec![
        "keys-seal",
        "--schedule",
        &es,
        "--custody-secret",
        custody.to_str().unwrap(),
        "--sealed-dir",
        sealed.to_str().unwrap(),
        "--from-week",
        &from,
        "--through-week",
        &through,
    ];
    let out_arg = arg(&out);
    args.extend(["--out", &out_arg]);
    if !pinned {
        args.extend(["--schedule-public-key", &key]);
    }
    (run(&args), out)
}

/// Checks a load file against the committed sealed test keys and the test schedule.
fn check_load(out: &Path, expected: &[(Kind, u64)]) {
    let load = SealLoad::parse(&std::fs::read(out).unwrap()).unwrap();
    assert_eq!(load.keys().collect::<Vec<_>>(), expected);
    let schedule = test_schedule();
    for &(kind, epoch) in expected {
        let sealed = std::fs::read(
            ops_fixtures()
                .join("sealed")
                .join(custody::sealed_file_name(kind, epoch)),
        )
        .unwrap();
        let signer = custody::unseal(load.get(kind, epoch).unwrap(), kind, epoch, &sealed).unwrap();
        assert_eq!(
            signer.public_key(),
            &schedule.key(kind, epoch).unwrap().public_key
        );
    }
}

#[test]
fn keys_seal_writes_a_load_that_opens_every_listed_key() {
    let dir = tempfile::tempdir().unwrap();
    let custody = custody_file(dir.path());
    let sealed = ops_fixtures().join("sealed");
    let ((status, lines), out) = keys_seal(dir.path(), &sealed, 2960, 2966, &custody, false);
    assert_eq!(status, Status::Ok, "{lines:?}");
    // Weeks 2960..2966 touch invite epochs 740 and 741 and credit epochs 227 and 228 (week 2964
    // starts credit epoch 228); the credit epoch before 227 is not in the schedule.
    let mut expected: Vec<(Kind, u64)> = (2960..=2966).map(|w| (Kind::Access, w)).collect();
    expected.extend([
        (Kind::Invite, 740),
        (Kind::Invite, 741),
        (Kind::Credit, 227),
        (Kind::Credit, 228),
    ]);
    check_load(&out, &expected);
    assert_eq!(lines.len(), expected.len() + 1);
    assert!(lines[..expected.len()]
        .iter()
        .all(|l| l.code == Code::SealKeyReady));
    let last = lines.last().unwrap();
    assert_eq!(last.code, Code::SealLoadWritten);
    assert_eq!(num(last, Field::Entries), Some(expected.len() as u64));
}

#[test]
fn keys_seal_keeps_the_previous_credit_epoch_for_refresh() {
    let dir = tempfile::tempdir().unwrap();
    let custody = custody_file(dir.path());
    let sealed = ops_fixtures().join("sealed");
    let ((status, lines), out) = keys_seal(dir.path(), &sealed, 2977, LAST_WEEK, &custody, false);
    assert_eq!(status, Status::Ok, "{lines:?}");
    let mut expected: Vec<(Kind, u64)> = (2977..=LAST_WEEK).map(|w| (Kind::Access, w)).collect();
    expected.extend([
        (Kind::Invite, 744),
        (Kind::Invite, 745),
        (Kind::Credit, 228),
        (Kind::Credit, 229),
    ]);
    check_load(&out, &expected);
}

#[test]
fn keys_seal_refuses_what_it_cannot_prove() {
    let dir = tempfile::tempdir().unwrap();
    let custody = custody_file(dir.path());
    let sealed = ops_fixtures().join("sealed");

    let ((status, lines), out) =
        keys_seal(dir.path(), &sealed, 2980, LAST_WEEK + 1, &custody, false);
    assert_eq!(status, Status::Refused);
    let last = lines.last().unwrap();
    assert_eq!(last.code, Code::KeyMissing);
    assert_eq!(num(last, Field::Epoch), Some(LAST_WEEK + 1));
    assert!(!out.exists());

    let other = write(dir.path(), "other.secret", &[9u8; 32]);
    let (result, _) = keys_seal(dir.path(), &sealed, 2960, 2960, &other, false);
    assert_refused(&result, Code::SealRefused, "open");

    let (result, _) = keys_seal(dir.path(), &sealed, 2960, 2960, &custody, true);
    assert_refused(&result, Code::EsRefused, "no-pinned-key");

    // The file of week 2961 presented as week 2960.
    let copy = dir.path().join("copy");
    copy_sealed(&copy);
    let name = |w| custody::sealed_file_name(Kind::Access, w);
    std::fs::copy(copy.join(name(2961)), copy.join(name(2960))).unwrap();
    let (result, _) = keys_seal(dir.path(), &copy, 2960, 2960, &custody, false);
    assert_refused(&result, Code::SealRefused, "wrong-key");

    // The key of week 2961 sealed correctly as week 2960: it opens but is not the ES key.
    let der = test_keys()
        .into_iter()
        .find(|(k, e, _)| *k == Kind::Access && *e == 2961)
        .unwrap()
        .2;
    let secret = CustodySecret::from_bytes(custody_seed());
    let resealed = custody::seal(
        &secret.seal_key(Kind::Access, 2960),
        Kind::Access,
        2960,
        &der,
        &SystemRandom::new(),
    )
    .unwrap();
    std::fs::write(copy.join(name(2960)), resealed).unwrap();
    let (result, _) = keys_seal(dir.path(), &copy, 2960, 2960, &custody, false);
    assert_refused(&result, Code::SealRefused, "mismatch");

    std::fs::remove_file(copy.join(name(2960))).unwrap();
    let (result, _) = keys_seal(dir.path(), &copy, 2960, 2960, &custody, false);
    assert_refused(&result, Code::IoError, "read");
    assert_eq!(
        word(result.1.last().unwrap(), Field::Flag),
        Some("sealed-dir")
    );

    write(dir.path(), "load.ghkl", b"existing");
    let (result, _) = keys_seal(dir.path(), &sealed, 2960, 2960, &custody, false);
    assert_refused(&result, Code::IoError, "exists");

    let (result, _) = keys_seal(dir.path(), &sealed, 2961, 2960, &custody, false);
    assert_refused(&result, Code::Usage, "bad-value");
}
