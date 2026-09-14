//! The payout workstation's commands (design §9.5 steps 2–4, §19.7; runbook P1). The workstation
//! is a separate host with its own view-only wallet-rpc and trusted monerod; its view dump (the
//! saved answer of `get_transfers {"in":true,"account_index":0}`) is the independent measure of
//! the revenue, and its ledger ([`crate::ledger`]) the record of every payout.
//!
//! - `payout-check`: the batch file's signature under the ops key; its network; every payout
//!   address (§7.7); the ledger's rules (a batch id once and a claim once per batch, else the
//!   batch is refused; an entry whose claim id an earlier batch had, or whose payout address was
//!   seen before, is recorded refused and the rest of the batch is taken, so neither a claimant's
//!   address nor its claim id can stall the batch, §19.27); the **cumulative cap**
//!   `paid_so_far + payable ≤ 10 % × Σ incoming to minors ≥ 1 since the treasury's restore
//!   height` (payable: the batch total less its refused entries; qualifying transfers of the view
//!   dump: at least 10 confirmations, `unlock_time` 0, not double-spent); and the issuer's
//!   cumulative credited revenue not above that incoming. Then the batch and its entries are
//!   appended to the ledger.
//! - `payout-entry`: one state change of one entry: `built` (only while no other entry is built
//!   or signed and not yet submitted), `signed` (the txid of `sign_transfer` and the key images
//!   read from its `tx_raw_list` entry, distinct from every other entry's), `submitted`,
//!   `confirmed` (the workstation's `get_transfer_by_txid` answer: the same txid, type `out`, at
//!   least 10 confirmations), `abandoned` (a signed entry only with the daemon's
//!   `is_key_image_spent` answer showing every one of its key images unspent).
//! - `payout-ack`: once every entry of the batch is confirmed or refused, the acknowledgement file
//!   for the issuer: each claim id of the batch file with its outcome, paid or refused. No txid
//!   goes to the issuer; the ledger keeps them.

use std::path::Path;

use ghost_entitlement::monero::{AddressPurpose, MoneroAddress, MoneroNetwork};
use ghost_issuer::payout::{AckFile, BatchFile, EntryOutcome, PayoutFileError};
use ghost_issuer::rail::monero::incoming_from_dump;
use ghost_issuer::reconcile::within_cap;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;

use crate::args::Flags;
use crate::input::{input_refused, read, read_text};
use crate::ledger::{EntryState, Ledger, Transition};
use crate::report::{network_name, Code, Field, Line, Sink};
use crate::{hexfmt, output, rawtx, Failure};

/// Confirmations a view-dump transfer needs to count as revenue, and a payout to be confirmed
/// (the ES constant of §7.3; the workstation holds no schedule).
pub const CONFIRMATIONS: u64 = 10;

fn refused(reason: &'static str) -> Line {
    Line::new(Code::PayoutRefused).word(Field::Reason, reason)
}

pub(crate) fn parse_network(flags: &Flags) -> Result<MoneroNetwork, Failure> {
    let text = flags.text("network")?;
    [
        MoneroNetwork::Mainnet,
        MoneroNetwork::Stagenet,
        MoneroNetwork::Regtest,
    ]
    .into_iter()
    .find(|n| network_name(*n) == text)
    .ok_or(Failure::usage("bad-value", Some("network")))
}

/// The batch file named by `--batch`, verified under `--ops-public-key`.
fn read_batch(flags: &Flags) -> Result<BatchFile, Failure> {
    let key = flags.hex32("ops-public-key")?;
    let bytes = read(&flags.path("batch")?, "batch")?;
    BatchFile::verify(&bytes, &key).map_err(|e| {
        Failure::refused(refused(match e {
            PayoutFileError::Signature => "signature",
            PayoutFileError::Format => "format",
        }))
    })
}

fn json(path: &Path, flag: &'static str) -> Result<Value, Failure> {
    serde_json::from_slice(&read(path, flag)?)
        .map_err(|_| Failure::refused(input_refused(flag, "json")))
}

/// Σ qualifying incoming transfers to minors ≥ 1 mined at or above `restore_height` in a view
/// dump.
pub(crate) fn view_incoming(path: &Path, restore_height: u64) -> Result<u64, Failure> {
    let entries = incoming_from_dump(json(path, "view-dump")?)
        .map_err(|_| Failure::refused(input_refused("view-dump", "transfers")))?;
    entries
        .iter()
        .filter(|e| {
            e.minor >= 1
                && e.unlock_time == 0
                && !e.double_spend_seen
                && e.confirmations >= CONFIRMATIONS
                && e.height.is_some_and(|h| h >= restore_height)
        })
        .try_fold(0u64, |sum, e| sum.checked_add(e.amount_atomic))
        .ok_or(Failure::refused(input_refused("view-dump", "overflow")))
}

/// The ledger at `path`, if the file exists.
pub(crate) fn load_ledger(path: &Path) -> Result<Option<Ledger>, Failure> {
    if !path.exists() {
        return Ok(None);
    }
    let text = read_text(path, "ledger")?;
    Ledger::parse(&text)
        .map(Some)
        .map_err(|e| Failure::refused(input_refused("ledger", e.reason).num(Field::Line, e.line)))
}

fn existing_ledger(path: &Path) -> Result<Ledger, Failure> {
    load_ledger(path)?.ok_or(Failure::refused(input_refused("ledger", "missing")))
}

const CHECK_FLAGS: [&str; 6] = [
    "batch",
    "ops-public-key",
    "network",
    "view-dump",
    "restore-height",
    "ledger",
];

/// `payout-check` (§9.5 step 2, §19.7 point 2).
pub fn check(argv: &[String], sink: &mut dyn Sink) -> Result<(), Failure> {
    let flags = Flags::parse(argv, &CHECK_FLAGS)?;
    let network = parse_network(&flags)?;
    let restore_height = flags.u64("restore-height")?;
    let ledger_path = flags.path("ledger")?;
    let view = flags.path("view-dump")?;
    let file = read_batch(&flags)?;
    let batch_line = |line: Line| line.hex(Field::Batch, &file.batch_id);
    if file.network != network {
        return Err(Failure::refused(batch_line(refused("network"))));
    }
    for (k, e) in file.entries.iter().enumerate() {
        if MoneroAddress::parse(e.address_text(), network, AddressPurpose::Payout).is_err() {
            return Err(Failure::refused(
                batch_line(refused("address")).num(Field::Entry, k as u64),
            ));
        }
    }
    let incoming = view_incoming(&view, restore_height)?;
    let (mut ledger, exists) = match load_ledger(&ledger_path)? {
        Some(l) => (l, true),
        None => {
            let mut salt = [0u8; 32];
            SystemRandom::new()
                .fill(&mut salt)
                .map_err(|_| Failure::refused(input_refused("ledger", "random")))?;
            (Ledger::new(salt), false)
        }
    };
    let paid_so_far = ledger.paid_so_far();
    let records = ledger
        .accept(&file)
        .map_err(|e| Failure::refused(batch_line(refused(e.reason))))?;
    let (refused_entries, payable) = ledger
        .batch(&file.batch_id)
        .map_or((0, file.total), |b| (b.refused(), b.payable()));
    let amounts = |line: Line| {
        line.num(Field::PaidSoFar, paid_so_far)
            .num(Field::Total, file.total)
            .num(Field::Incoming, incoming)
    };
    if !within_cap(paid_so_far.saturating_add(payable), incoming) {
        return Err(Failure::refused(amounts(batch_line(refused("cap")))));
    }
    if file.cumulative_credited > incoming {
        return Err(Failure::refused(amounts(batch_line(refused(
            "credited-above-view",
        )))));
    }
    if exists {
        output::append_ledger(&ledger_path, &records, "ledger")?;
    } else {
        output::create_ledger(
            &ledger_path,
            &format!("{}{records}", ledger.header()),
            "ledger",
        )?;
    }
    sink.emit(amounts(
        batch_line(Line::new(Code::PayoutAccepted))
            .num(Field::Entries, file.entries.len() as u64)
            .num(Field::Refused, refused_entries as u64),
    ));
    Ok(())
}

const ENTRY_FLAGS: [&str; 8] = [
    "ledger",
    "batch-id",
    "entry",
    "to",
    "raw-tx",
    "txid",
    "transfer",
    "spent-status",
];

/// The `get_transfer_by_txid` answer (or its `result`) of the payout `txid`: type `out` and at
/// least [`CONFIRMATIONS`].
fn confirmed_transfer(value: &Value, txid: &[u8; 32]) -> bool {
    let result = value.get("result").unwrap_or(value);
    let Some(t) = result.get("transfer") else {
        return false;
    };
    t.get("txid").and_then(Value::as_str) == Some(hexfmt::encode(txid).as_str())
        && t.get("type").and_then(Value::as_str) == Some("out")
        && t.get("confirmations")
            .and_then(Value::as_u64)
            .is_some_and(|c| c >= CONFIRMATIONS)
}

/// The daemon's `is_key_image_spent` answer for `images`: every status 0 (unspent).
fn all_unspent(value: &Value, images: usize) -> bool {
    value
        .get("spent_status")
        .and_then(Value::as_array)
        .is_some_and(|s| s.len() == images && s.iter().all(|v| v.as_u64() == Some(0)))
}

/// `payout-entry` (§9.5 step 3, §19.7 point 1).
pub fn entry(argv: &[String], sink: &mut dyn Sink) -> Result<(), Failure> {
    let flags = Flags::parse(argv, &ENTRY_FLAGS)?;
    let ledger_path = flags.path("ledger")?;
    let id: [u8; 16] = flags.hex("batch-id")?;
    let k = usize::try_from(flags.u64("entry")?)
        .map_err(|_| Failure::usage("bad-value", Some("entry")))?;
    let to = Transition::parse(flags.text("to")?).ok_or(Failure::usage("bad-value", Some("to")))?;
    let mut ledger = existing_ledger(&ledger_path)?;
    let current = ledger
        .batch(&id)
        .and_then(|b| b.entries.get(k))
        .cloned()
        .ok_or(Failure::refused(
            refused("unknown-entry").hex(Field::Batch, &id),
        ))?;
    let base = ["ledger", "batch-id", "entry", "to"];
    let (txid, images) = match to {
        Transition::Built | Transition::Submitted => {
            flags.only(&base)?;
            (None, Vec::new())
        }
        Transition::Signed => {
            flags.only(&[base[0], base[1], base[2], base[3], "raw-tx", "txid"])?;
            let raw = read_text(&flags.path("raw-tx")?, "raw-tx")?;
            let images = hexfmt::decode(raw.trim_end())
                .and_then(|bytes| rawtx::key_images(&bytes))
                .ok_or(Failure::refused(input_refused("raw-tx", "transaction")))?;
            (Some(flags.hex32("txid")?), images)
        }
        Transition::Confirmed => {
            flags.only(&[base[0], base[1], base[2], base[3], "transfer"])?;
            let answer = json(&flags.path("transfer")?, "transfer")?;
            let ok = current
                .txid
                .is_some_and(|txid| confirmed_transfer(&answer, &txid));
            if current.state == EntryState::Submitted && !ok {
                return Err(Failure::refused(
                    refused("not-confirmed")
                        .hex(Field::Batch, &id)
                        .num(Field::Entry, k as u64),
                ));
            }
            (None, Vec::new())
        }
        Transition::Abandoned => {
            if current.state == EntryState::Signed {
                flags.only(&[base[0], base[1], base[2], base[3], "spent-status"])?;
                let answer = json(&flags.path("spent-status")?, "spent-status")?;
                if !all_unspent(&answer, current.images.len()) {
                    return Err(Failure::refused(
                        refused("spent")
                            .hex(Field::Batch, &id)
                            .num(Field::Entry, k as u64),
                    ));
                }
            } else {
                flags.only(&base)?;
            }
            (None, Vec::new())
        }
    };
    let image_count = images.len() as u64;
    let record = ledger.transition(&id, k, to, txid, images).map_err(|e| {
        Failure::refused(
            refused(e.reason)
                .hex(Field::Batch, &id)
                .num(Field::Entry, k as u64),
        )
    })?;
    output::append_ledger(&ledger_path, &record, "ledger")?;
    let state = ledger
        .batch(&id)
        .map_or(EntryState::Accepted, |b| b.entries[k].state);
    let mut line = Line::new(Code::EntryState)
        .hex(Field::Batch, &id)
        .num(Field::Entry, k as u64)
        .word(Field::State, state.word());
    if let Some(txid) = txid {
        line = line.hex(Field::Txid, &txid).num(Field::Images, image_count);
    }
    sink.emit(line);
    Ok(())
}

const ACK_FLAGS: [&str; 4] = ["ledger", "batch", "ops-public-key", "out"];

/// `payout-ack` (§9.5 step 4).
pub fn ack(argv: &[String], sink: &mut dyn Sink) -> Result<(), Failure> {
    let flags = Flags::parse(argv, &ACK_FLAGS)?;
    let ledger_path = flags.path("ledger")?;
    let out = flags.path("out")?;
    let file = read_batch(&flags)?;
    let mut ledger = existing_ledger(&ledger_path)?;
    let batch = ledger
        .batch(&file.batch_id)
        .cloned()
        .ok_or(Failure::refused(
            refused("unknown-batch").hex(Field::Batch, &file.batch_id),
        ))?;
    let matches = batch.entries.len() == file.entries.len()
        && batch
            .entries
            .iter()
            .zip(&file.entries)
            .all(|(l, f)| l.claim == ledger.claim_hash(&f.claim_id) && l.amount == f.amount);
    if !matches {
        return Err(Failure::refused(
            refused("batch-mismatch").hex(Field::Batch, &file.batch_id),
        ));
    }
    let record = ledger
        .ack(&file.batch_id)
        .map_err(|e| Failure::refused(refused(e.reason).hex(Field::Batch, &file.batch_id)))?;
    let entries = file
        .entries
        .iter()
        .zip(&batch.entries)
        .map(|(f, l)| {
            let outcome = if l.state == EntryState::Refused {
                EntryOutcome::Refused
            } else {
                EntryOutcome::Paid
            };
            (f.claim_id, outcome)
        })
        .collect();
    let ack = AckFile {
        batch_id: file.batch_id,
        entries,
    };
    let bytes = ack
        .encode()
        .map_err(|_| Failure::refused(refused("format")))?;
    output::write_ack(&out, &bytes, "out")?;
    output::append_ledger(&ledger_path, &record, "ledger")?;
    sink.emit(
        Line::new(Code::AckWritten)
            .hex(Field::Batch, &file.batch_id)
            .num(Field::Entries, ack.entries.len() as u64),
    );
    Ok(())
}
