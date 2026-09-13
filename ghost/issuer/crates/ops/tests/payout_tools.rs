//! The payout workstation's commands and `reconcile-check`, run in process (design §9.5 steps
//! 2–4, §19.7, §6.9; runbooks P1, R2): the batch file's signature, network and addresses, the
//! cumulative 10 % cap against the workstation's view dump, the ledger's per-entry states with the
//! sequential build and distinct input key images, the acknowledgement file, and the
//! reconciliation of an `issuer.redb` snapshot with relay aggregates and the view.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use ghost_entitlement::monero::MoneroNetwork;
use ghost_issuer::payout::{AckFile, BatchFile, BatchLine, EntryOutcome, OpsKey};
use ghost_issuer::reconcile::{self, CounterId};
use ghost_issuer::store::{RedbStore, Store};
use ghost_issuer_ops::ledger::{Ledger, HEADER};
use ghost_issuer_ops::report::{Code, Field, Line, Value};
use ghost_issuer_ops::Status;

/// Published mainnet addresses (regtest uses the mainnet prefixes), from
/// `protocol/test-vectors/monero_addresses.txt`.
const ADDRESSES: [&str; 6] = [
    "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
    "42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm",
    "44Kbx4sJ7JDRDV5aAhLJzQCjDz2ViLRduE3ijDZu3osWKBjMGkV1XPk4pfDUMqt1Aiezvephdqm6YD19GKFD9ZcXVUTp6BW",
    "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H",
    "84QRUYawRNrU3NN1VpFRndSukeyEb3Xpv8qZjjsoJZnTYpDYceuUTpog13D7qPxpviS7J29bSgSkR11hFFoXWk2yNdsR9WF",
    "8AsN91rznfkBGTY8psSNkJBg9SZgxxGGRUhGwRptBhgr5XSQ1XzmA9m8QAnoxydecSh5aLJXdrgXwTDMMZ1AuXsN1EX5Mtm",
];
const STAGENET_ADDRESS: &str =
    "53teqCAESLxeJ1REzGMAat1ZeHvuajvDiXqboEocPaDRRmqWoVPzy46GLo866qRFjbNhfkNckyhST3WEvBviDwpUDd7DSzB";
const PRICE: u64 = 200_000_000_000;
/// Monday 2026-09-28 12:00 UTC, access week 2960.
const NOW: &str = "1790596800";

fn ops() -> OpsKey {
    OpsKey::from_seed(&[0x0b; 32])
}

/// A batch of `(amount, address index)` entries whose claim ids start at `claim_base`.
fn batch(id: u8, entries: &[(u64, &str)], claim_base: u8) -> BatchFile {
    let entries: Vec<BatchLine> = entries
        .iter()
        .enumerate()
        .map(|(i, (amount, address))| BatchLine {
            claim_id: [claim_base + i as u8; 16],
            address: address.as_bytes().try_into().unwrap(),
            amount: *amount,
        })
        .collect();
    BatchFile {
        network: MoneroNetwork::Regtest,
        batch_id: [id; 16],
        week: 2960,
        total: entries.iter().map(|e| e.amount).sum(),
        entries,
        cumulative_credited: 0,
    }
}

fn write_batch(dir: &Path, name: &str, file: &BatchFile) -> PathBuf {
    write(dir, name, &file.sign(&ops()).unwrap())
}

/// A saved `get_transfers` answer: `(amount, minor, confirmations, height)` incoming transfers.
fn view_dump(dir: &Path, name: &str, transfers: &[(u64, u32, u64, u64)]) -> PathBuf {
    let entries: Vec<String> = transfers
        .iter()
        .enumerate()
        .map(|(i, (amount, minor, confirmations, height))| {
            format!(
                "{{\"amount\":{amount},\"confirmations\":{confirmations},\
                 \"double_spend_seen\":false,\"height\":{height},\
                 \"subaddr_index\":{{\"major\":0,\"minor\":{minor}}},\"timestamp\":0,\
                 \"txid\":\"{:064x}\",\"type\":\"in\",\"unlock_time\":0}}",
                i + 1
            )
        })
        .collect();
    let text = format!(
        "{{\"id\":\"0\",\"jsonrpc\":\"2.0\",\"result\":{{\"in\":[{}]}}}}",
        entries.join(",")
    );
    write(dir, name, text.as_bytes())
}

fn check(batch: &Path, view: &Path, ledger: &Path, network: &str) -> (Status, Vec<Line>) {
    run(&[
        "payout-check",
        "--batch",
        &arg(batch),
        "--ops-public-key",
        &hex(&ops().public()),
        "--network",
        network,
        "--view-dump",
        &arg(view),
        "--restore-height",
        "10",
        "--ledger",
        &arg(ledger),
    ])
}

/// The prefix of a signed RingCT transaction whose inputs carry `images` (its RingCT part is not
/// read), as hex text.
fn raw_tx(dir: &Path, name: &str, images: &[[u8; 32]]) -> PathBuf {
    let mut out = vec![0x02, 0x00, images.len() as u8];
    for image in images {
        out.extend_from_slice(&[0x02, 0x00, 0x02, 0x81, 0x01, 0x05]);
        out.extend_from_slice(image);
    }
    out.extend_from_slice(&[0x02, 0x00]);
    write(dir, name, format!("{}\n", hex(&out)).as_bytes())
}

fn ok(result: &(Status, Vec<Line>), code: Code) -> Line {
    let (status, lines) = result;
    let rendered: Vec<String> = lines.iter().map(Line::render).collect();
    assert_eq!(*status, Status::Ok, "{rendered:?}");
    let last = lines.last().unwrap().clone();
    assert_eq!(last.code, code, "{rendered:?}");
    last
}

#[test]
fn payout_check_keeps_the_cumulative_payouts_within_ten_percent_of_the_view() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let ledger = d.join("ledger.txt");
    // Counted: 10·PRICE to minor 1. Not counted: the change to minor 0, a transfer below 10
    // confirmations, one mined below the restore height.
    let view = view_dump(
        d,
        "view.json",
        &[
            (10 * PRICE, 1, 20, 100),
            (10 * PRICE, 0, 20, 100),
            (5 * PRICE, 2, 9, 100),
            (5 * PRICE, 3, 20, 9),
        ],
    );
    let first = write_batch(
        d,
        "b1.ghpb",
        &batch(
            1,
            &[(PRICE / 2, ADDRESSES[0]), (PRICE / 2, ADDRESSES[3])],
            0,
        ),
    );
    let line = ok(
        &check(&first, &view, &ledger, "regtest"),
        Code::PayoutAccepted,
    );
    assert_eq!(num(&line, Field::Total), Some(PRICE));
    assert_eq!(num(&line, Field::PaidSoFar), Some(0));
    assert_eq!(num(&line, Field::Incoming), Some(10 * PRICE));
    assert_eq!(num(&line, Field::Entries), Some(2));
    let text = std::fs::read_to_string(&ledger).unwrap();
    assert!(text.starts_with(HEADER));
    assert_eq!(text.lines().count(), 4, "header, batch and two entries");

    // A second batch over the same revenue: paid_so_far + total > 10 % (§19.7 point 2).
    let second = write_batch(d, "b2.ghpb", &batch(2, &[(1, ADDRESSES[1])], 10));
    let r = check(&second, &view, &ledger, "regtest");
    assert_refused(&r, Code::PayoutRefused, "cap");
    assert_eq!(num(r.1.last().unwrap(), Field::PaidSoFar), Some(PRICE));
    assert_eq!(
        std::fs::read_to_string(&ledger).unwrap(),
        text,
        "nothing recorded"
    );

    // A batch id and a claim id are accepted once (an honest issuer never repeats them); a
    // repeated address refuses its entry only (a_repeated_payout_address_refuses_its_entry_...).
    assert_refused(
        &check(&first, &view, &ledger, "regtest"),
        Code::PayoutRefused,
        "batch-seen",
    );
    let claim = write_batch(d, "b3.ghpb", &batch(3, &[(1, ADDRESSES[1])], 0));
    assert_refused(
        &check(&claim, &view, &ledger, "regtest"),
        Code::PayoutRefused,
        "claim-seen",
    );

    // More revenue measured by the view: the second batch now fits.
    let more = view_dump(d, "view2.json", &[(20 * PRICE, 1, 20, 100)]);
    let line = ok(
        &check(&second, &more, &ledger, "regtest"),
        Code::PayoutAccepted,
    );
    assert_eq!(num(&line, Field::PaidSoFar), Some(PRICE));
}

/// S6 review (MONEY-1, PRIV-1): a payout address is a claimant's input, so a repeat refuses its own
/// entry and never the batch: the entry is recorded refused (never built, never paid, not counted
/// in the cumulative payouts) and every other entry of the batch is paid. Repeats are an address
/// paid in an earlier batch (the issuer has deleted it) and a second occurrence in one batch.
#[test]
fn a_repeated_payout_address_refuses_its_entry_and_the_batch_is_paid() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let ledger = d.join("ledger.txt");
    let view = view_dump(d, "view.json", &[(100 * PRICE, 1, 20, 100)]);
    let first = write_batch(d, "b1.ghpb", &batch(1, &[(PRICE / 10, ADDRESSES[0])], 0));
    ok(
        &check(&first, &view, &ledger, "regtest"),
        Code::PayoutAccepted,
    );
    let entries = [
        (PRICE / 10, ADDRESSES[0]),
        (PRICE / 10, ADDRESSES[1]),
        (PRICE / 10, ADDRESSES[1]),
    ];
    let second = write_batch(d, "b2.ghpb", &batch(2, &entries, 10));
    let line = ok(
        &check(&second, &view, &ledger, "regtest"),
        Code::PayoutAccepted,
    );
    assert!(line.render().contains(" refused=2"), "{}", line.render());
    assert_eq!(num(&line, Field::Refused), Some(2));
    assert_eq!(num(&line, Field::PaidSoFar), Some(PRICE / 10));
    let third = write_batch(d, "b3.ghpb", &batch(3, &[(1, ADDRESSES[2])], 20));
    let line = ok(
        &check(&third, &view, &ledger, "regtest"),
        Code::PayoutAccepted,
    );
    assert_eq!(
        num(&line, Field::PaidSoFar),
        Some(2 * PRICE / 10),
        "a refused entry is not a payout"
    );

    // The refused entries never move; the payable one is paid; the acknowledgement names each
    // entry's outcome.
    for k in [0, 2] {
        assert_refused(
            &entry_in(&ledger, 2, k, "built", &[]),
            Code::PayoutRefused,
            "state",
        );
    }
    let tx = arg(&raw_tx(d, "tx.hex", &[[7; 32]]));
    let txid = hex(&[0xc1; 32]);
    ok(&entry_in(&ledger, 2, 1, "built", &[]), Code::EntryState);
    ok(
        &entry_in(&ledger, 2, 1, "signed", &["--raw-tx", &tx, "--txid", &txid]),
        Code::EntryState,
    );
    ok(&entry_in(&ledger, 2, 1, "submitted", &[]), Code::EntryState);
    let t = arg(&transfer(d, "t.json", &[0xc1; 32], 10));
    ok(
        &entry_in(&ledger, 2, 1, "confirmed", &["--transfer", &t]),
        Code::EntryState,
    );
    let out = d.join("ack.ghpa");
    let line = ok(
        &run(&[
            "payout-ack",
            "--ledger",
            &arg(&ledger),
            "--batch",
            &arg(&second),
            "--ops-public-key",
            &hex(&ops().public()),
            "--out",
            &arg(&out),
        ]),
        Code::AckWritten,
    );
    assert_eq!(num(&line, Field::Entries), Some(3));
    let ack = AckFile::parse(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(
        ack.entries,
        vec![
            ([10; 16], EntryOutcome::Refused),
            ([11; 16], EntryOutcome::Paid),
            ([12; 16], EntryOutcome::Refused)
        ]
    );
}

#[test]
fn payout_check_refuses_forged_files_other_networks_bad_addresses_and_views() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let ledger = d.join("ledger.txt");
    let view = view_dump(d, "view.json", &[(10 * PRICE, 1, 20, 100)]);
    let file = batch(1, &[(PRICE, ADDRESSES[0])], 0);
    let other_key = write(
        d,
        "other.ghpb",
        &file.sign(&OpsKey::from_seed(&[1; 32])).unwrap(),
    );
    assert_refused(
        &check(&other_key, &view, &ledger, "regtest"),
        Code::PayoutRefused,
        "signature",
    );
    let mut bytes = file.sign(&ops()).unwrap();
    bytes[30] ^= 1;
    let tampered = write(d, "tampered.ghpb", &bytes);
    assert_refused(
        &check(&tampered, &view, &ledger, "regtest"),
        Code::PayoutRefused,
        "signature",
    );
    let good = write_batch(d, "good.ghpb", &file);
    assert_refused(
        &check(&good, &view, &ledger, "mainnet"),
        Code::PayoutRefused,
        "network",
    );
    let r = check(&good, &view, &ledger, "moonnet");
    assert_refused(&r, Code::Usage, "bad-value");
    let stagenet = write_batch(
        d,
        "stagenet.ghpb",
        &batch(2, &[(1, ADDRESSES[1]), (1, STAGENET_ADDRESS)], 10),
    );
    let r = check(&stagenet, &view, &ledger, "regtest");
    assert_refused(&r, Code::PayoutRefused, "address");
    assert_eq!(num(r.1.last().unwrap(), Field::Entry), Some(1));
    let not_json = write(d, "bad.json", b"{\"result\":");
    assert_refused(
        &check(&good, &not_json, &ledger, "regtest"),
        Code::InputRefused,
        "json",
    );
    let not_transfers = write(d, "neg.json", b"{\"in\":[{\"amount\":-1}]}");
    assert_refused(
        &check(&good, &not_transfers, &ledger, "regtest"),
        Code::InputRefused,
        "transfers",
    );
    let mut credited = batch(3, &[(1, ADDRESSES[2])], 20);
    credited.cumulative_credited = 10 * PRICE + 1;
    let credited = write_batch(d, "credited.ghpb", &credited);
    assert_refused(
        &check(&credited, &view, &ledger, "regtest"),
        Code::PayoutRefused,
        "credited-above-view",
    );
    assert!(!ledger.exists(), "a refused check creates no ledger");
    ok(
        &check(&good, &view, &ledger, "regtest"),
        Code::PayoutAccepted,
    );
}

/// A ledger holding batch 1 of `n` entries of `PRICE / 10` each.
fn accepted(d: &Path, n: usize) -> (PathBuf, BatchFile, PathBuf) {
    let ledger = d.join("ledger.txt");
    let entries: Vec<(u64, &str)> = (0..n).map(|i| (PRICE / 10, ADDRESSES[i])).collect();
    let file = batch(1, &entries, 0);
    let path = write_batch(d, "b1.ghpb", &file);
    let view = view_dump(d, "view.json", &[(10 * PRICE, 1, 20, 100)]);
    ok(
        &check(&path, &view, &ledger, "regtest"),
        Code::PayoutAccepted,
    );
    (ledger, file, path)
}

fn entry(ledger: &Path, k: usize, to: &str, extra: &[&str]) -> (Status, Vec<Line>) {
    entry_in(ledger, 1, k, to, extra)
}

/// `payout-entry` for entry `k` of batch `[id; 16]`.
fn entry_in(ledger: &Path, id: u8, k: usize, to: &str, extra: &[&str]) -> (Status, Vec<Line>) {
    let k = k.to_string();
    let batch = hex(&[id; 16]);
    let mut args = vec![
        "payout-entry",
        "--ledger",
        ledger.to_str().unwrap(),
        "--batch-id",
        &batch,
        "--entry",
        &k,
        "--to",
        to,
    ];
    args.extend_from_slice(extra);
    run(&args)
}

fn transfer(d: &Path, name: &str, txid: &[u8; 32], confirmations: u64) -> PathBuf {
    let text = format!(
        "{{\"transfer\":{{\"txid\":\"{}\",\"type\":\"out\",\"confirmations\":{confirmations},\
         \"amount\":1}}}}",
        hex(txid)
    );
    write(d, name, text.as_bytes())
}

#[test]
fn payout_entries_are_built_one_at_a_time_with_distinct_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (ledger, _, _) = accepted(d, 3);
    let (a0, a1) = (hex(&[0xa0; 32]), hex(&[0xa1; 32]));
    ok(&entry(&ledger, 0, "built", &[]), Code::EntryState);
    assert_refused(
        &entry(&ledger, 1, "built", &[]),
        Code::PayoutRefused,
        "sequence",
    );
    let tx0 = arg(&raw_tx(d, "tx0.hex", &[[1; 32], [2; 32]]));
    let line = ok(
        &entry(&ledger, 0, "signed", &["--raw-tx", &tx0, "--txid", &a0]),
        Code::EntryState,
    );
    assert_eq!(word(&line, Field::State), Some("signed"));
    assert_eq!(num(&line, Field::Images), Some(2));
    assert_refused(
        &entry(&ledger, 1, "built", &[]),
        Code::PayoutRefused,
        "sequence",
    );
    ok(&entry(&ledger, 0, "submitted", &[]), Code::EntryState);
    ok(&entry(&ledger, 1, "built", &[]), Code::EntryState);
    let reused = arg(&raw_tx(d, "tx1.hex", &[[2; 32]]));
    assert_refused(
        &entry(&ledger, 1, "signed", &["--raw-tx", &reused, "--txid", &a1]),
        Code::PayoutRefused,
        "key-image-reused",
    );
    let tx1 = arg(&raw_tx(d, "tx1b.hex", &[[3; 32]]));
    assert_refused(
        &entry(&ledger, 1, "signed", &["--raw-tx", &tx1, "--txid", &a0]),
        Code::PayoutRefused,
        "txid",
    );
    let garbage = arg(&write(d, "garbage.hex", b"0100\n"));
    assert_refused(
        &entry(&ledger, 1, "signed", &["--raw-tx", &garbage, "--txid", &a1]),
        Code::InputRefused,
        "transaction",
    );
    ok(
        &entry(&ledger, 1, "signed", &["--raw-tx", &tx1, "--txid", &a1]),
        Code::EntryState,
    );
    // A signed entry is rebuilt only once its inputs are proven unspent.
    let spent = arg(&write(
        d,
        "spent.json",
        b"{\"spent_status\":[1],\"status\":\"OK\"}",
    ));
    assert_refused(
        &entry(&ledger, 1, "abandoned", &["--spent-status", &spent]),
        Code::PayoutRefused,
        "spent",
    );
    let unspent = arg(&write(
        d,
        "unspent.json",
        b"{\"spent_status\":[0],\"status\":\"OK\"}",
    ));
    let line = ok(
        &entry(&ledger, 1, "abandoned", &["--spent-status", &unspent]),
        Code::EntryState,
    );
    assert_eq!(word(&line, Field::State), Some("accepted"));
    assert_refused(
        &entry(&ledger, 0, "abandoned", &[]),
        Code::PayoutRefused,
        "state",
    );
    // Confirmation: the workstation's transfer with the entry's txid and 10 confirmations.
    let five = arg(&transfer(d, "t5.json", &[0xa0; 32], 5));
    assert_refused(
        &entry(&ledger, 0, "confirmed", &["--transfer", &five]),
        Code::PayoutRefused,
        "not-confirmed",
    );
    let other = arg(&transfer(d, "tother.json", &[0xa1; 32], 50));
    assert_refused(
        &entry(&ledger, 0, "confirmed", &["--transfer", &other]),
        Code::PayoutRefused,
        "not-confirmed",
    );
    let ten = arg(&transfer(d, "t10.json", &[0xa0; 32], 10));
    let line = ok(
        &entry(&ledger, 0, "confirmed", &["--transfer", &ten]),
        Code::EntryState,
    );
    assert_eq!(word(&line, Field::State), Some("confirmed"));
    assert_refused(
        &entry(&ledger, 5, "built", &[]),
        Code::PayoutRefused,
        "unknown-entry",
    );
    assert_refused(
        &entry(&ledger, 2, "sideways", &[]),
        Code::Usage,
        "bad-value",
    );
}

#[test]
fn payout_ack_writes_the_acknowledgement_once_every_entry_is_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (ledger, file, path) = accepted(d, 2);
    let txids = [[0xb0u8; 32], [0xb1u8; 32]];
    let ack = |out: &str| {
        run(&[
            "payout-ack",
            "--ledger",
            ledger.to_str().unwrap(),
            "--batch",
            &arg(&path),
            "--ops-public-key",
            &hex(&ops().public()),
            "--out",
            &arg(&d.join(out)),
        ])
    };
    for (k, txid) in txids.iter().enumerate() {
        let tx = arg(&raw_tx(d, &format!("tx{k}.hex"), &[[k as u8 + 1; 32]]));
        ok(&entry(&ledger, k, "built", &[]), Code::EntryState);
        ok(
            &entry(
                &ledger,
                k,
                "signed",
                &["--raw-tx", &tx, "--txid", &hex(txid)],
            ),
            Code::EntryState,
        );
        ok(&entry(&ledger, k, "submitted", &[]), Code::EntryState);
        if k == 0 {
            assert_refused(&ack("early.ghpa"), Code::PayoutRefused, "not-confirmed");
        }
        let t = arg(&transfer(d, &format!("t{k}.json"), txid, 10));
        ok(
            &entry(&ledger, k, "confirmed", &["--transfer", &t]),
            Code::EntryState,
        );
    }
    let line = ok(&ack("ack.ghpa"), Code::AckWritten);
    assert_eq!(num(&line, Field::Entries), Some(2));
    // S6 review (PRIV-4): the issuer learns each entry's outcome, never its payout transaction.
    assert_eq!(
        std::fs::read(d.join("ack.ghpa")).unwrap().len(),
        4 + 1 + 16 + 2 + 2 * (16 + 1),
        "claim id and outcome per entry, no txid"
    );
    let written = AckFile::parse(&std::fs::read(d.join("ack.ghpa")).unwrap()).unwrap();
    assert_eq!(written.batch_id, file.batch_id);
    assert_eq!(
        written.entries,
        vec![
            (file.entries[0].claim_id, EntryOutcome::Paid),
            (file.entries[1].claim_id, EntryOutcome::Paid)
        ]
    );
    assert_refused(&ack("again.ghpa"), Code::PayoutRefused, "acked");
    let other = write_batch(d, "other.ghpb", &batch(9, &[(1, ADDRESSES[5])], 90));
    let r = run(&[
        "payout-ack",
        "--ledger",
        ledger.to_str().unwrap(),
        "--batch",
        &arg(&other),
        "--ops-public-key",
        &hex(&ops().public()),
        "--out",
        &arg(&d.join("other.ghpa")),
    ]);
    assert_refused(&r, Code::PayoutRefused, "unknown-batch");
}

/// An `issuer.redb` snapshot with the counters of one XMR pack of base week 2960 under the test
/// schedule (3 slots a week, 16 access positions per slot, 2 invites, 1 credit).
fn snapshot(d: &Path, extra: &[(CounterId, u64, u64)]) -> PathBuf {
    let path = d.join("issuer.redb");
    fill(&RedbStore::open(&path).unwrap(), extra);
    path
}

/// Commits the counters of a small issuer (plus `extra`) in one write transaction.
fn fill(store: &RedbStore, extra: &[(CounterId, u64, u64)]) {
    let mut tx = store.write().unwrap();
    let mut counts = vec![
        (CounterId::PacksXmr, 2960, 1),
        (CounterId::XmrCreditedAtomic, 2960, PRICE),
        (CounterId::SignedInvite, 740, 2),
        (CounterId::SignedCredit, 227, 1),
    ];
    counts.extend((2960..2965).map(|w| (CounterId::SignedAccess, w, 48)));
    counts.extend_from_slice(extra);
    for (id, index, delta) in counts {
        reconcile::add(&mut *tx, id, index, delta).unwrap();
    }
    tx.commit().unwrap();
}

/// Set in the child process of `reconcile_check_reads_the_database_of_a_killed_issuer`: the
/// database it writes.
const KILLED_WRITER_DB: &str = "GHOST_TEST_KILLED_WRITER_DB";

/// Runbook B1 (review finding INFRA-1): the hourly snapshot copies the `issuer.redb` of an issuer
/// ended by a signal, never one that closed its database (redb writes the allocator state a
/// read-only open needs when the `Database` is dropped, and a killed process drops nothing). The
/// child process commits as the issuer does and exits without running a destructor, as under
/// SIGKILL; the copy of its file must still be read by `reconcile-check` and `counters-export`.
#[test]
fn reconcile_check_reads_the_database_of_a_killed_issuer() {
    if let Some(path) = std::env::var_os(KILLED_WRITER_DB) {
        let store = RedbStore::open(Path::new(&path)).unwrap();
        fill(&store, &[]);
        std::process::exit(0);
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let live = d.join("issuer.redb");
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "reconcile_check_reads_the_database_of_a_killed_issuer",
            "--exact",
            "--test-threads",
            "1",
        ])
        .env(KILLED_WRITER_DB, &live)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(child.success(), "the writer process failed: {child}");
    // The B1 copy (`install -m 0600`), taken once the writer is gone.
    let copy = d.join("issuer-2026092812.redb");
    std::fs::copy(&live, &copy).unwrap();
    let before = std::fs::read(&copy).unwrap();
    let line = ok(&reconcile(&copy, &[]), Code::ReconciliationOk);
    assert_eq!(num(&line, Field::Relays), Some(0));
    // The snapshot is recovered in a private copy, never in place (B1 mounts it read-only).
    assert_eq!(std::fs::read(&copy).unwrap(), before);
    let counters = d.join("counters.txt");
    let (status, lines) = run(&[
        "counters-export",
        "--database",
        &arg(&copy),
        "--out",
        &arg(&counters),
    ]);
    let rendered: Vec<String> = lines.iter().map(Line::render).collect();
    assert_eq!(status, Status::Ok, "{rendered:?}");
    assert_eq!(rendered, vec!["COUNTERS_WRITTEN counters=10".to_string()]);
}

fn reconcile(database: &Path, extra: &[&str]) -> (Status, Vec<Line>) {
    let es = arg(&test_schedule_path());
    let key = schedule_public_hex();
    let db = arg(database);
    let mut args = vec![
        "reconcile-check",
        "--database",
        &db,
        "--schedule",
        &es,
        "--schedule-public-key",
        &key,
        "--now",
        NOW,
    ];
    args.extend_from_slice(extra);
    run(&args)
}

#[test]
fn reconcile_check_reads_a_snapshot_with_relay_aggregates_and_the_view() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let db = snapshot(d, &[]);
    let line = ok(&reconcile(&db, &[]), Code::ReconciliationOk);
    assert_eq!(num(&line, Field::Relays), Some(0));

    // Relay operators report per slot; only the sum over all slots of a week is bounded (§19.3).
    let a = arg(&write(
        d,
        "relay-a.txt",
        b"# slot 0\nweek 2960 slot 0 redemptions 48\nweek 2961 slot 0 redemptions 10\n",
    ));
    let b = arg(&write(
        d,
        "relay-b.txt",
        b"week 2961 slot 1 redemptions 38\n\n",
    ));
    let line = ok(
        &reconcile(&db, &["--relay-counts", &a, "--relay-counts", &b]),
        Code::ReconciliationOk,
    );
    assert_eq!(
        (num(&line, Field::Weeks), num(&line, Field::Relays)),
        (Some(2), Some(2))
    );
    let c = arg(&write(
        d,
        "relay-c.txt",
        b"week 2960 slot 2 redemptions 1\n",
    ));
    let r = reconcile(&db, &["--relay-counts", &a, "--relay-counts", &c]);
    assert_refused(&r, Code::ReconciliationMismatch, "relay-redemptions");
    assert_eq!(num(r.1.last().unwrap(), Field::Week), Some(2960));
    let dup = arg(&write(
        d,
        "relay-dup.txt",
        b"week 2960 slot 0 redemptions 1\n",
    ));
    assert_refused(
        &reconcile(&db, &["--relay-counts", &a, "--relay-counts", &dup]),
        Code::InputRefused,
        "duplicate",
    );
    let bad = arg(&write(
        d,
        "relay-bad.txt",
        b"week 2960 slot zero redemptions 1\n",
    ));
    assert_refused(
        &reconcile(&db, &["--relay-counts", &bad]),
        Code::InputRefused,
        "line",
    );

    // The workstation's view and ledger are checked against exported counters, never next to the
    // database (reconcile_check_runs_on_the_workstation_from_exported_counters).
}

/// `reconcile-check` of a counters file.
fn reconcile_counters(counters: &Path, extra: &[&str]) -> (Status, Vec<Line>) {
    let es = arg(&test_schedule_path());
    let key = schedule_public_hex();
    let c = arg(counters);
    let mut args = vec![
        "reconcile-check",
        "--counters",
        &c,
        "--schedule",
        &es,
        "--schedule-public-key",
        &key,
        "--now",
        NOW,
    ];
    args.extend_from_slice(extra);
    run(&args)
}

/// S6 review (PRIV-2): the workstation never needs `issuer.redb`. `counters-export` runs on the
/// issuer host against a snapshot there and writes the counters only (aggregates, no identifier);
/// `reconcile-check --counters` checks them on the workstation with the relay counts, its view and
/// its ledger. A database is never combined with the workstation's view or ledger.
#[test]
fn reconcile_check_runs_on_the_workstation_from_exported_counters() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let db = snapshot(d, &[]);
    let counters = d.join("counters.txt");
    let (status, lines) = run(&[
        "counters-export",
        "--database",
        &arg(&db),
        "--out",
        &arg(&counters),
    ]);
    let rendered: Vec<String> = lines.iter().map(Line::render).collect();
    assert_eq!(status, Status::Ok, "{rendered:?}");
    assert_eq!(rendered, vec!["COUNTERS_WRITTEN counters=10".to_string()]);
    let text = std::fs::read_to_string(&counters).unwrap();
    assert_eq!(
        text.lines().count(),
        11,
        "a header and one line per counter"
    );
    assert!(text
        .lines()
        .skip(1)
        .all(|l| l.split(' ').count() == 3 && l.bytes().all(|b| b.is_ascii_digit() || b == b' ')));

    let line = ok(&reconcile_counters(&counters, &[]), Code::ReconciliationOk);
    assert_eq!(num(&line, Field::Relays), Some(0));

    // The workstation's view: the credited revenue must have arrived, payouts within 10 %.
    let view = arg(&view_dump(d, "view.json", &[(PRICE, 1, 20, 100)]));
    ok(
        &reconcile_counters(&counters, &["--view-dump", &view, "--restore-height", "10"]),
        Code::ReconciliationOk,
    );
    let short = arg(&view_dump(d, "short.json", &[(PRICE - 1, 1, 20, 100)]));
    assert_refused(
        &reconcile_counters(
            &counters,
            &["--view-dump", &short, "--restore-height", "10"],
        ),
        Code::ReconciliationMismatch,
        "view-below-credited",
    );
    let mut ledger = Ledger::new([4; 32]);
    let text = ledger
        .accept(&batch(1, &[(PRICE / 10 + 1, ADDRESSES[0])], 0))
        .unwrap();
    let ledger_path = arg(&write(
        d,
        "ledger.txt",
        format!("{}{text}", ledger.header()).as_bytes(),
    ));
    assert_refused(
        &reconcile_counters(
            &counters,
            &[
                "--view-dump",
                &view,
                "--restore-height",
                "10",
                "--ledger",
                &ledger_path,
            ],
        ),
        Code::ReconciliationMismatch,
        "payout-cap",
    );
    assert_refused(
        &reconcile_counters(&counters, &["--ledger", &ledger_path]),
        Code::Usage,
        "missing-flag",
    );

    // The database stays on the issuer host: never with the workstation's view or ledger.
    for extra in [
        vec!["--view-dump", view.as_str(), "--restore-height", "10"],
        vec!["--ledger", ledger_path.as_str()],
        vec!["--counters", c_path(&counters)],
    ] {
        assert_refused(&reconcile(&db, &extra), Code::Usage, "conflicting-flags");
    }
    let bad = write(d, "bad.txt", b"ghost-issuer-counters 1\n3 2960 x\n");
    assert_refused(&reconcile_counters(&bad, &[]), Code::InputRefused, "line");
}

fn c_path(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn reconcile_check_reports_every_mismatch_and_refuses_what_is_not_a_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let db = snapshot(
        d,
        &[
            (CounterId::SignedAccess, 2961, 1),
            (CounterId::SignedCredit, 227, 1),
        ],
    );
    let (status, lines) = reconcile(&db, &[]);
    assert_eq!(status, Status::Refused);
    let reasons: Vec<(Option<&str>, Option<&Value>)> = lines
        .iter()
        .map(|l| {
            (
                word(l, Field::Reason),
                field(l, Field::Week).or(field(l, Field::Epoch)),
            )
        })
        .collect();
    assert_eq!(
        reasons,
        vec![
            (Some("signed-access"), Some(&Value::Num(2961))),
            (Some("signed-credit"), Some(&Value::Num(227))),
        ]
    );
    assert!(lines.iter().all(|l| l.code == Code::ReconciliationMismatch));
    let not_db = write(d, "not.redb", b"not a database");
    assert_refused(&reconcile(&not_db, &[]), Code::InputRefused, "open");
}
