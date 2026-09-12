//! The payout workstation's ledger (design §9.5 steps 2–4, §19.7, §19.15 point 3): an append-only
//! text file, one record per line, replayed in full by every payout command. The same rules apply
//! to a record read back and to a new one, so a ledger that does not replay is refused whole.
//!
//! ```text
//! ghost-payout-ledger 1 salt <64 hex>
//! batch <batch id, 32 hex> week <n> total <n> entries <n>
//! entry <batch id> <k> claim <64 hex> address <64 hex> amount <n>
//! built <batch id> <k>
//! signed <batch id> <k> txid <64 hex> images <64 hex>[,<64 hex>]...
//! submitted <batch id> <k>
//! confirmed <batch id> <k>
//! abandoned <batch id> <k>
//! acked <batch id>
//! ```
//!
//! **What it keeps** (§19.15): per entry the batch id, a salted hash of the claim id, a salted
//! hash of the payout address, the amount, the state, the txid and the input key images; per
//! batch its total, so the cumulative payouts survive the deletion of batch files. The salt is
//! drawn when the ledger is created.
//!
//! **Rules.** A batch id, a claim and a payout address are accepted once (§19.7 point 2). The
//! entries of a batch follow its batch record in order, and their amounts sum to its total. Per
//! entry `accepted → built → signed → submitted → confirmed` (§19.7 point 1): an entry is built
//! only while no entry of the ledger is built or signed and not yet submitted, so entry k + 1 is
//! built only after entry k was submitted (a watch-only `transfer` reserves nothing: two entries
//! built from one wallet state could select the same inputs); a signed entry names its txid and
//! the key images of its inputs, distinct from every other entry's; a built or signed entry may be
//! abandoned back to accepted (a signed one only once its inputs are proven unspent, checked by
//! `payout-entry`; the runbook destroys its signed transaction), a submitted one never. A batch is
//! acknowledged once, when every entry is confirmed.

use std::collections::{BTreeMap, BTreeSet};

use ghost_issuer::payout::BatchFile;
use sha2::{Digest, Sha256};

use crate::args::parse_u64;
use crate::hexfmt;

pub const HEADER: &str = "ghost-payout-ledger 1";
const CLAIM_DOMAIN: &[u8] = b"ghost/v1/ledger-claim";
const ADDRESS_DOMAIN: &[u8] = b"ghost/v1/ledger-address";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryState {
    Accepted,
    Built,
    Signed,
    Submitted,
    Confirmed,
}

impl EntryState {
    pub fn word(self) -> &'static str {
        match self {
            EntryState::Accepted => "accepted",
            EntryState::Built => "built",
            EntryState::Signed => "signed",
            EntryState::Submitted => "submitted",
            EntryState::Confirmed => "confirmed",
        }
    }
}

/// A requested change of an entry's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transition {
    Built,
    Signed,
    Submitted,
    Confirmed,
    Abandoned,
}

impl Transition {
    pub const ALL: [Transition; 5] = [
        Transition::Built,
        Transition::Signed,
        Transition::Submitted,
        Transition::Confirmed,
        Transition::Abandoned,
    ];

    pub fn word(self) -> &'static str {
        match self {
            Transition::Built => "built",
            Transition::Signed => "signed",
            Transition::Submitted => "submitted",
            Transition::Confirmed => "confirmed",
            Transition::Abandoned => "abandoned",
        }
    }

    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.word() == word)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    pub claim: [u8; 32],
    pub address: [u8; 32],
    pub amount: u64,
    pub state: EntryState,
    pub txid: Option<[u8; 32]>,
    pub images: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerBatch {
    pub week: u64,
    pub total: u64,
    /// The number of entries its batch record announced.
    pub expected: usize,
    pub entries: Vec<LedgerEntry>,
    pub acked: bool,
}

impl LedgerBatch {
    fn complete(&self) -> bool {
        self.entries.len() == self.expected
    }
}

/// A record the ledger refused: its line (from 1; the next line for a new record) and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerError {
    pub line: u64,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Record {
    Batch {
        id: [u8; 16],
        week: u64,
        total: u64,
        entries: usize,
    },
    Entry {
        id: [u8; 16],
        k: usize,
        claim: [u8; 32],
        address: [u8; 32],
        amount: u64,
    },
    State {
        id: [u8; 16],
        k: usize,
        to: Transition,
        txid: Option<[u8; 32]>,
        images: Vec<[u8; 32]>,
    },
    Acked {
        id: [u8; 16],
    },
}

impl Record {
    fn text(&self) -> String {
        match self {
            Record::Batch {
                id,
                week,
                total,
                entries,
            } => format!(
                "batch {} week {week} total {total} entries {entries}\n",
                hexfmt::encode(id)
            ),
            Record::Entry {
                id,
                k,
                claim,
                address,
                amount,
            } => format!(
                "entry {} {k} claim {} address {} amount {amount}\n",
                hexfmt::encode(id),
                hexfmt::encode(claim),
                hexfmt::encode(address)
            ),
            Record::State {
                id,
                k,
                to,
                txid,
                images,
            } => {
                let mut line = format!("{} {} {k}", to.word(), hexfmt::encode(id));
                if let Some(txid) = txid {
                    let images: Vec<String> = images.iter().map(|i| hexfmt::encode(i)).collect();
                    line.push_str(&format!(
                        " txid {} images {}",
                        hexfmt::encode(txid),
                        images.join(",")
                    ));
                }
                line.push('\n');
                line
            }
            Record::Acked { id } => format!("acked {}\n", hexfmt::encode(id)),
        }
    }

    fn parse(line: &str) -> Option<Self> {
        let w: Vec<&str> = line.split(' ').collect();
        let hex_n = |s: &str| hexfmt::decode(s);
        let id = |s: &str| hex_n(s).and_then(|b| <[u8; 16]>::try_from(b).ok());
        let h32 = |s: &str| hex_n(s).and_then(|b| <[u8; 32]>::try_from(b).ok());
        let index = |s: &str| parse_u64(s).and_then(|n| usize::try_from(n).ok());
        match w.as_slice() {
            ["batch", b, "week", week, "total", total, "entries", n] => Some(Record::Batch {
                id: id(b)?,
                week: parse_u64(week)?,
                total: parse_u64(total)?,
                entries: index(n)?,
            }),
            ["entry", b, k, "claim", c, "address", a, "amount", amount] => Some(Record::Entry {
                id: id(b)?,
                k: index(k)?,
                claim: h32(c)?,
                address: h32(a)?,
                amount: parse_u64(amount)?,
            }),
            ["signed", b, k, "txid", t, "images", images] => Some(Record::State {
                id: id(b)?,
                k: index(k)?,
                to: Transition::Signed,
                txid: Some(h32(t)?),
                images: images.split(',').map(h32).collect::<Option<Vec<_>>>()?,
            }),
            [word, b, k] if *word != "signed" => Some(Record::State {
                id: id(b)?,
                k: index(k)?,
                to: Transition::parse(word)?,
                txid: None,
                images: Vec::new(),
            }),
            ["acked", b] => Some(Record::Acked { id: id(b)? }),
            _ => None,
        }
    }
}

/// The ledger, replayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ledger {
    salt: [u8; 32],
    batches: BTreeMap<[u8; 16], LedgerBatch>,
    /// Records so far (the line of the next record is `records + 2`).
    records: u64,
}

impl Ledger {
    pub fn new(salt: [u8; 32]) -> Self {
        Self {
            salt,
            batches: BTreeMap::new(),
            records: 0,
        }
    }

    /// The first line of a new ledger.
    pub fn header(&self) -> String {
        format!("{HEADER} salt {}\n", hexfmt::encode(&self.salt))
    }

    /// Replays a ledger file.
    pub fn parse(text: &str) -> Result<Self, LedgerError> {
        let mut lines = text.split_inclusive('\n');
        let refused = |line: u64, reason| LedgerError { line, reason };
        let header = lines
            .next()
            .and_then(|l| l.strip_suffix('\n'))
            .ok_or(refused(1, "header"))?;
        let salt = header
            .strip_prefix(HEADER)
            .and_then(|rest| rest.strip_prefix(" salt "))
            .and_then(hexfmt::decode)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or(refused(1, "header"))?;
        let mut ledger = Self::new(salt);
        for line in lines {
            let n = ledger.records + 2;
            let body = line.strip_suffix('\n').ok_or(refused(n, "torn"))?;
            let record = Record::parse(body).ok_or(refused(n, "record"))?;
            ledger.apply(&record).map_err(|reason| refused(n, reason))?;
        }
        Ok(ledger)
    }

    /// The salted hash of a claim id.
    pub fn claim_hash(&self, claim_id: &[u8; 16]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(CLAIM_DOMAIN);
        h.update(self.salt);
        h.update(claim_id);
        h.finalize().into()
    }

    /// The salted hash of a payout address.
    pub fn address_hash(&self, address: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(ADDRESS_DOMAIN);
        h.update(self.salt);
        h.update(address.as_bytes());
        h.finalize().into()
    }

    pub fn batch(&self, id: &[u8; 16]) -> Option<&LedgerBatch> {
        self.batches.get(id)
    }

    /// Σ totals of every batch the ledger accepted: the cumulative payouts of §19.7 point 2
    /// (accepted batches count before they are paid).
    pub fn paid_so_far(&self) -> u64 {
        self.batches
            .values()
            .map(|b| b.total)
            .fold(0u64, u64::saturating_add)
    }

    fn entries(&self) -> impl Iterator<Item = (&[u8; 16], usize, &LedgerEntry)> {
        self.batches
            .iter()
            .flat_map(|(id, b)| b.entries.iter().enumerate().map(move |(k, e)| (id, k, e)))
    }

    fn apply(&mut self, record: &Record) -> Result<(), &'static str> {
        match record {
            Record::Batch {
                id,
                week,
                total,
                entries,
            } => {
                if self.batches.contains_key(id) {
                    return Err("batch-seen");
                }
                if self.batches.values().any(|b| !b.complete()) {
                    return Err("sequence");
                }
                if *entries == 0 {
                    return Err("record");
                }
                self.batches.insert(
                    *id,
                    LedgerBatch {
                        week: *week,
                        total: *total,
                        expected: *entries,
                        entries: Vec::new(),
                        acked: false,
                    },
                );
            }
            Record::Entry {
                id,
                k,
                claim,
                address,
                amount,
            } => {
                if self.entries().any(|(_, _, e)| e.claim == *claim) {
                    return Err("claim-seen");
                }
                if self.entries().any(|(_, _, e)| e.address == *address) {
                    return Err("address-repeated");
                }
                let batch = self.batches.get_mut(id).ok_or("sequence")?;
                if batch.complete() || *k != batch.entries.len() || *amount == 0 {
                    return Err("sequence");
                }
                batch.entries.push(LedgerEntry {
                    claim: *claim,
                    address: *address,
                    amount: *amount,
                    state: EntryState::Accepted,
                    txid: None,
                    images: Vec::new(),
                });
                if batch.complete() {
                    let sum = batch
                        .entries
                        .iter()
                        .map(|e| e.amount)
                        .try_fold(0u64, |a, b| a.checked_add(b));
                    if sum != Some(batch.total) {
                        return Err("total");
                    }
                }
            }
            Record::State {
                id,
                k,
                to,
                txid,
                images,
            } => self.transition_entry(id, *k, *to, *txid, images)?,
            Record::Acked { id } => {
                let batch = self.batches.get_mut(id).ok_or("unknown-batch")?;
                if batch.acked {
                    return Err("acked");
                }
                if !batch.complete()
                    || batch
                        .entries
                        .iter()
                        .any(|e| e.state != EntryState::Confirmed)
                {
                    return Err("not-confirmed");
                }
                batch.acked = true;
            }
        }
        self.records += 1;
        Ok(())
    }

    fn transition_entry(
        &mut self,
        id: &[u8; 16],
        k: usize,
        to: Transition,
        txid: Option<[u8; 32]>,
        images: &[[u8; 32]],
    ) -> Result<(), &'static str> {
        let state = self
            .batches
            .get(id)
            .filter(|b| b.complete())
            .and_then(|b| b.entries.get(k))
            .map(|e| e.state)
            .ok_or("unknown-entry")?;
        match (to, state) {
            (Transition::Built, EntryState::Accepted) => {
                if self
                    .entries()
                    .any(|(_, _, e)| matches!(e.state, EntryState::Built | EntryState::Signed))
                {
                    return Err("sequence");
                }
            }
            (Transition::Signed, EntryState::Built) => {
                let txid = txid.ok_or("txid")?;
                let distinct: BTreeSet<[u8; 32]> = images.iter().copied().collect();
                if images.is_empty() || distinct.len() != images.len() {
                    return Err("key-images");
                }
                for (other_id, other_k, e) in self.entries() {
                    if (other_id, other_k) == (id, k) {
                        continue;
                    }
                    if e.txid == Some(txid) {
                        return Err("txid");
                    }
                    if e.images.iter().any(|i| distinct.contains(i)) {
                        return Err("key-image-reused");
                    }
                }
            }
            (Transition::Submitted, EntryState::Signed)
            | (Transition::Confirmed, EntryState::Submitted)
            | (Transition::Abandoned, EntryState::Built | EntryState::Signed) => {}
            _ => return Err("state"),
        }
        let entry = self
            .batches
            .get_mut(id)
            .and_then(|b| b.entries.get_mut(k))
            .ok_or("unknown-entry")?;
        match to {
            Transition::Built => entry.state = EntryState::Built,
            Transition::Signed => {
                entry.state = EntryState::Signed;
                entry.txid = txid;
                entry.images = images.to_vec();
            }
            Transition::Submitted => entry.state = EntryState::Submitted,
            Transition::Confirmed => entry.state = EntryState::Confirmed,
            Transition::Abandoned => {
                entry.state = EntryState::Accepted;
                entry.txid = None;
                entry.images.clear();
            }
        }
        Ok(())
    }

    /// Applies `records` to a copy; on success the ledger becomes the copy and their text is
    /// returned (to be appended to the file).
    fn commit(&mut self, records: &[Record]) -> Result<String, LedgerError> {
        let mut next = self.clone();
        let mut text = String::new();
        for record in records {
            let line = next.records + 2;
            next.apply(record)
                .map_err(|reason| LedgerError { line, reason })?;
            text.push_str(&record.text());
        }
        *self = next;
        Ok(text)
    }

    /// `payout-check`: the batch and its entries (§9.5 step 2).
    pub fn accept(&mut self, file: &BatchFile) -> Result<String, LedgerError> {
        let mut records = vec![Record::Batch {
            id: file.batch_id,
            week: file.week,
            total: file.total,
            entries: file.entries.len(),
        }];
        for (k, e) in file.entries.iter().enumerate() {
            records.push(Record::Entry {
                id: file.batch_id,
                k,
                claim: self.claim_hash(&e.claim_id),
                address: self.address_hash(e.address_text()),
                amount: e.amount,
            });
        }
        self.commit(&records)
    }

    /// `payout-entry`: one state change of entry `k` (§9.5 step 3, §19.7 point 1).
    pub fn transition(
        &mut self,
        id: &[u8; 16],
        k: usize,
        to: Transition,
        txid: Option<[u8; 32]>,
        images: Vec<[u8; 32]>,
    ) -> Result<String, LedgerError> {
        self.commit(&[Record::State {
            id: *id,
            k,
            to,
            txid,
            images,
        }])
    }

    /// `payout-ack`: every entry of the batch is confirmed (§9.5 step 4).
    pub fn ack(&mut self, id: &[u8; 16]) -> Result<String, LedgerError> {
        self.commit(&[Record::Acked { id: *id }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_entitlement::monero::MoneroNetwork;
    use ghost_issuer::payout::BatchLine;

    fn file(id: u8, n: usize, first_claim: u8) -> BatchFile {
        let entries: Vec<BatchLine> = (0..n)
            .map(|i| BatchLine {
                claim_id: [first_claim + i as u8; 16],
                address: [b'a' + first_claim + i as u8; 95],
                amount: 10,
            })
            .collect();
        BatchFile {
            network: MoneroNetwork::Regtest,
            batch_id: [id; 16],
            week: 2960,
            total: 10 * n as u64,
            entries,
            cumulative_credited: 0,
        }
    }

    fn replay(ledger: &Ledger, appended: &str) -> Ledger {
        let text = format!("{}{appended}", ledger.header());
        Ledger::parse(&text).unwrap()
    }

    #[test]
    fn a_ledger_replays_to_what_was_appended() {
        let mut l = Ledger::new([9; 32]);
        let mut text = l.accept(&file(1, 2, 0)).unwrap();
        text += &l
            .transition(&[1; 16], 0, Transition::Built, None, Vec::new())
            .unwrap();
        text += &l
            .transition(
                &[1; 16],
                0,
                Transition::Signed,
                Some([5; 32]),
                vec![[6; 32], [7; 32]],
            )
            .unwrap();
        assert_eq!(replay(&l, &text), l);
        assert_eq!(l.paid_so_far(), 20);
    }

    #[test]
    fn entries_are_built_one_at_a_time() {
        let mut l = Ledger::new([9; 32]);
        l.accept(&file(1, 2, 0)).unwrap();
        l.transition(&[1; 16], 0, Transition::Built, None, Vec::new())
            .unwrap();
        let second = l.transition(&[1; 16], 1, Transition::Built, None, Vec::new());
        assert_eq!(second.unwrap_err().reason, "sequence");
        l.transition(
            &[1; 16],
            0,
            Transition::Signed,
            Some([5; 32]),
            vec![[6; 32]],
        )
        .unwrap();
        let second = l.transition(&[1; 16], 1, Transition::Built, None, Vec::new());
        assert_eq!(
            second.unwrap_err().reason,
            "sequence",
            "signed, not submitted"
        );
        l.transition(&[1; 16], 0, Transition::Submitted, None, Vec::new())
            .unwrap();
        l.transition(&[1; 16], 1, Transition::Built, None, Vec::new())
            .unwrap();
        // The second entry may not reuse the first one's input or txid.
        let reused = l.transition(
            &[1; 16],
            1,
            Transition::Signed,
            Some([8; 32]),
            vec![[6; 32]],
        );
        assert_eq!(reused.unwrap_err().reason, "key-image-reused");
        let same_txid = l.transition(
            &[1; 16],
            1,
            Transition::Signed,
            Some([5; 32]),
            vec![[9; 32]],
        );
        assert_eq!(same_txid.unwrap_err().reason, "txid");
        l.transition(
            &[1; 16],
            1,
            Transition::Signed,
            Some([8; 32]),
            vec![[9; 32]],
        )
        .unwrap();
        assert_eq!(
            l.transition(&[1; 16], 0, Transition::Abandoned, None, Vec::new())
                .unwrap_err()
                .reason,
            "state",
            "a submitted entry is never abandoned"
        );
        l.transition(&[1; 16], 1, Transition::Abandoned, None, Vec::new())
            .unwrap();
        assert_eq!(
            l.batch(&[1; 16]).unwrap().entries[1].images,
            Vec::<[u8; 32]>::new()
        );
    }

    #[test]
    fn batches_claims_and_addresses_are_accepted_once() {
        let mut l = Ledger::new([9; 32]);
        l.accept(&file(1, 2, 0)).unwrap();
        assert_eq!(l.accept(&file(1, 1, 50)).unwrap_err().reason, "batch-seen");
        assert_eq!(l.accept(&file(2, 1, 1)).unwrap_err().reason, "claim-seen");
        let mut repeated = file(3, 1, 60);
        repeated.entries[0].address = [b'a'; 95];
        assert_eq!(l.accept(&repeated).unwrap_err().reason, "address-repeated");
        assert_eq!(l.paid_so_far(), 20, "a refused batch changes nothing");
        l.accept(&file(4, 1, 70)).unwrap();
        assert_eq!(l.paid_so_far(), 30);
    }

    #[test]
    fn a_batch_is_acknowledged_once_all_entries_are_confirmed() {
        let mut l = Ledger::new([9; 32]);
        l.accept(&file(1, 1, 0)).unwrap();
        assert_eq!(l.ack(&[1; 16]).unwrap_err().reason, "not-confirmed");
        for (to, txid, images) in [
            (Transition::Built, None, vec![]),
            (Transition::Signed, Some([5; 32]), vec![[6; 32]]),
            (Transition::Submitted, None, vec![]),
            (Transition::Confirmed, None, vec![]),
        ] {
            l.transition(&[1; 16], 0, to, txid, images).unwrap();
        }
        l.ack(&[1; 16]).unwrap();
        assert_eq!(l.ack(&[1; 16]).unwrap_err().reason, "acked");
    }

    #[test]
    fn a_damaged_ledger_is_refused_whole() {
        let mut l = Ledger::new([9; 32]);
        let text = l.accept(&file(1, 2, 0)).unwrap();
        let whole = format!("{}{text}", l.header());
        assert!(Ledger::parse(&whole).is_ok());
        assert_eq!(
            Ledger::parse(&whole[..whole.len() - 1]).unwrap_err().reason,
            "torn"
        );
        let swapped = whole.replace("entry", "entrx");
        assert_eq!(Ledger::parse(&swapped).unwrap_err().line, 3);
        assert_eq!(Ledger::parse("not a ledger\n").unwrap_err().line, 1);
        // An entry record without its batch, or out of order.
        let lines: Vec<&str> = whole.lines().collect();
        let reordered = format!("{}\n{}\n{}\n{}\n", lines[0], lines[1], lines[3], lines[2]);
        assert_eq!(Ledger::parse(&reordered).unwrap_err().reason, "sequence");
    }
}
