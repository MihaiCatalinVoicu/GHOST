//! Issuer storage (Phase 8 design §6.1, §6.2): `issuer.redb`, `SCHEMA_VERSION = 1` (any other
//! version is refused), `Durability::Immediate` on every write transaction.
//!
//! State goes through the [`Store`] trait (redb in production, [`RedbStore`]); the typed rows of
//! §6.1 are encoded here with fixed lengths and big-endian integers, so every table is a byte-slice
//! table and a key's byte order is its numeric order. Test doubles (`FaultyStore`) wrap a
//! `RedbStore` in `tests/` only.
//!
//! | table | key | value |
//! |---|---|---|
//! | `meta` | ASCII name | u64 |
//! | `es_memory` | fact u8 (1 key, 2 slot set, 3 price, 4 revocation) ‖ kind u8 (0 for 2, 3) ‖ epoch u64 | [32] |
//! | `address_pool` | minor u32 | 95-byte subaddress |
//! | `invoice` | [16] | [`InvoiceRow`] (285 bytes) |
//! | `claim_index` | claim hash [32] | invoice id [16] |
//! | `minor_index` | minor u32 | invoice id [16] |
//! | `credited_tx` | invoice id [16] ‖ txid [32] | height u64 |
//! | `invite_nullifier` | epoch u64 ‖ N [32] | trial digest [32] |
//! | `credit_nullifier` | epoch u64 ‖ N [32] | use u8 ‖ ref [16] (zero except for a refresh) |
//! | `claim` | claim id [16] | [`ClaimRow`] (153 bytes) |
//! | `batch` | batch id [16] | [`BatchRow`] (35 bytes) |
//! | `counter` | index u64 ‖ counter id u8 | u64 |
//!
//! Recorded deviations from the §6.1 table: the `es_memory` key carries the token kind (key and
//! revocation facts are per (kind, epoch); a bare epoch collides across kinds); the invoice row
//! carries its 95-byte subaddress (the byte-identical `RequestInvoice` re-serve of §5.6 step 2 must
//! return it after the pool entry is gone, also after a restore); the batch row adds
//! `cumulative_credited` (a field of the signed batch file, re-exported byte for byte) and
//! `paid_week` (the week of the acknowledgement: the paid batch's claims are deleted two weeks
//! later and the batch six weeks later, at least the 7 and 30 days of §6.1, with no time finer
//! than a week, §19.15).

use std::path::Path;

use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};

/// On-disk schema version of `issuer.redb`.
pub const SCHEMA_VERSION: u64 = 1;
/// Length of a Monero address (subaddress or standard) in its Base58 text form.
pub const ADDRESS_LEN: usize = 95;

type Bytes = TableDefinition<'static, &'static [u8], &'static [u8]>;

const META: Bytes = TableDefinition::new("meta");
const ES_MEMORY: Bytes = TableDefinition::new("es_memory");
const ADDRESS_POOL: Bytes = TableDefinition::new("address_pool");
const INVOICE: Bytes = TableDefinition::new("invoice");
const CLAIM_INDEX: Bytes = TableDefinition::new("claim_index");
const MINOR_INDEX: Bytes = TableDefinition::new("minor_index");
const CREDITED_TX: Bytes = TableDefinition::new("credited_tx");
const INVITE_NULLIFIER: Bytes = TableDefinition::new("invite_nullifier");
const CREDIT_NULLIFIER: Bytes = TableDefinition::new("credit_nullifier");
const CLAIM: Bytes = TableDefinition::new("claim");
const BATCH: Bytes = TableDefinition::new("batch");
const COUNTER: Bytes = TableDefinition::new("counter");

/// The tables of schema 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Table {
    Meta,
    EsMemory,
    AddressPool,
    Invoice,
    ClaimIndex,
    MinorIndex,
    CreditedTx,
    InviteNullifier,
    CreditNullifier,
    Claim,
    Batch,
    Counter,
}

impl Table {
    pub const ALL: [Table; 12] = [
        Table::Meta,
        Table::EsMemory,
        Table::AddressPool,
        Table::Invoice,
        Table::ClaimIndex,
        Table::MinorIndex,
        Table::CreditedTx,
        Table::InviteNullifier,
        Table::CreditNullifier,
        Table::Claim,
        Table::Batch,
        Table::Counter,
    ];

    fn definition(self) -> Bytes {
        match self {
            Table::Meta => META,
            Table::EsMemory => ES_MEMORY,
            Table::AddressPool => ADDRESS_POOL,
            Table::Invoice => INVOICE,
            Table::ClaimIndex => CLAIM_INDEX,
            Table::MinorIndex => MINOR_INDEX,
            Table::CreditedTx => CREDITED_TX,
            Table::InviteNullifier => INVITE_NULLIFIER,
            Table::CreditNullifier => CREDIT_NULLIFIER,
            Table::Claim => CLAIM,
            Table::Batch => BATCH,
            Table::Counter => COUNTER,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Table::Meta => "meta",
            Table::EsMemory => "es_memory",
            Table::AddressPool => "address_pool",
            Table::Invoice => "invoice",
            Table::ClaimIndex => "claim_index",
            Table::MinorIndex => "minor_index",
            Table::CreditedTx => "credited_tx",
            Table::InviteNullifier => "invite_nullifier",
            Table::CreditNullifier => "credit_nullifier",
            Table::Claim => "claim",
            Table::Batch => "batch",
            Table::Counter => "counter",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreError {
    /// The database failed (I/O, lock, transaction or commit error).
    Db,
    /// The database was written by another schema version, or is not an issuer database.
    Schema,
    /// A stored row does not decode (wrong length or an unknown code).
    Corrupt,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StoreError::Db => "issuer database failed",
            StoreError::Schema => "issuer database of another schema version",
            StoreError::Corrupt => "issuer database row does not decode",
        })
    }
}

impl std::error::Error for StoreError {}

macro_rules! db_error {
    ($($t:ty),*) => {$(
        impl From<$t> for StoreError {
            fn from(_: $t) -> Self {
                StoreError::Db
            }
        }
    )*};
}
db_error!(
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError,
    redb::SetDurabilityError
);

/// Rows of a range read: `(key, value)` pairs in key order.
pub type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// Reads of one transaction.
pub trait ReadTx {
    fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError>;
    /// Every `(key, value)` with `start <= key < end` (`end = None`: through the last key),
    /// ascending.
    fn range(&self, table: Table, start: &[u8], end: Option<&[u8]>) -> Result<Rows, StoreError>;
}

/// One write transaction: nothing is visible to other transactions before `commit`, and a
/// transaction dropped without `commit` leaves no trace.
pub trait WriteTx: ReadTx {
    fn put(&mut self, table: Table, key: &[u8], value: &[u8]) -> Result<(), StoreError>;
    fn delete(&mut self, table: Table, key: &[u8]) -> Result<(), StoreError>;
    /// Commits durably (`Durability::Immediate` for the redb store).
    fn commit(self: Box<Self>) -> Result<(), StoreError>;
}

/// The issuer's state. One writer at a time (redb): `write` waits for an open write transaction.
pub trait Store: Send + Sync {
    fn read(&self) -> Result<Box<dyn ReadTx + '_>, StoreError>;
    fn write(&self) -> Result<Box<dyn WriteTx + '_>, StoreError>;
}

/// The production store: `issuer.redb`.
pub struct RedbStore {
    db: Database,
}

impl RedbStore {
    /// Opens or creates the database. A new file gets every table and `schema_version = 1`; an
    /// existing file must carry exactly `schema_version = 1`.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let db = Database::create(path)?;
        let mut txn = db.begin_write()?;
        txn.set_durability(Durability::Immediate)?;
        {
            let existing = txn.list_tables()?.count();
            let mut meta = txn.open_table(META)?;
            let version = meta
                .get(MetaKey::SchemaVersion.name().as_bytes())?
                .map(|g| {
                    let v: [u8; 8] = g.value().try_into().unwrap_or([0xFF; 8]);
                    u64::from_be_bytes(v)
                });
            match version {
                Some(SCHEMA_VERSION) => {}
                // A database with tables but no version is not an issuer database of schema 1.
                None if existing == 0 => {
                    meta.insert(
                        MetaKey::SchemaVersion.name().as_bytes(),
                        SCHEMA_VERSION.to_be_bytes().as_slice(),
                    )?;
                }
                _ => return Err(StoreError::Schema),
            }
        }
        for table in Table::ALL {
            txn.open_table(table.definition())?;
        }
        txn.commit()?;
        Ok(Self { db })
    }
}

/// A read-only view of a copy of `issuer.redb` (runbook R2: `ghost-issuer-ops reconcile-check`
/// reads a snapshot, never the live database, which the issuer holds open). Another schema version
/// is refused.
pub struct RedbSnapshot {
    db: redb::ReadOnlyDatabase,
}

impl RedbSnapshot {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let snapshot = Self {
            db: redb::ReadOnlyDatabase::open(path)?,
        };
        if meta(&*snapshot.read()?, MetaKey::SchemaVersion)? != Some(SCHEMA_VERSION) {
            return Err(StoreError::Schema);
        }
        Ok(snapshot)
    }

    pub fn read(&self) -> Result<Box<dyn ReadTx + '_>, StoreError> {
        Ok(Box::new(RedbRead(self.db.begin_read()?)))
    }
}

struct RedbRead(redb::ReadTransaction);
struct RedbWrite(redb::WriteTransaction);

fn collect<T: ReadableTable<&'static [u8], &'static [u8]>>(
    table: &T,
    start: &[u8],
    end: Option<&[u8]>,
) -> Result<Rows, StoreError> {
    let iter = match end {
        Some(end) => table.range::<&[u8]>(start..end)?,
        None => table.range::<&[u8]>(start..)?,
    };
    let mut out = Vec::new();
    for item in iter {
        let (k, v) = item?;
        out.push((k.value().to_vec(), v.value().to_vec()));
    }
    Ok(out)
}

impl ReadTx for RedbRead {
    fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let t = self.0.open_table(table.definition())?;
        Ok(t.get(key)?.map(|g| g.value().to_vec()))
    }

    fn range(&self, table: Table, start: &[u8], end: Option<&[u8]>) -> Result<Rows, StoreError> {
        collect(&self.0.open_table(table.definition())?, start, end)
    }
}

impl ReadTx for RedbWrite {
    fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let t = self.0.open_table(table.definition())?;
        let value = t.get(key)?.map(|g| g.value().to_vec());
        Ok(value)
    }

    fn range(&self, table: Table, start: &[u8], end: Option<&[u8]>) -> Result<Rows, StoreError> {
        collect(&self.0.open_table(table.definition())?, start, end)
    }
}

impl WriteTx for RedbWrite {
    fn put(&mut self, table: Table, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.0.open_table(table.definition())?.insert(key, value)?;
        Ok(())
    }

    fn delete(&mut self, table: Table, key: &[u8]) -> Result<(), StoreError> {
        self.0.open_table(table.definition())?.remove(key)?;
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<(), StoreError> {
        self.0.commit()?;
        Ok(())
    }
}

impl Store for RedbStore {
    fn read(&self) -> Result<Box<dyn ReadTx + '_>, StoreError> {
        Ok(Box::new(RedbRead(self.db.begin_read()?)))
    }

    fn write(&self) -> Result<Box<dyn WriteTx + '_>, StoreError> {
        let mut txn = self.db.begin_write()?;
        txn.set_durability(Durability::Immediate)?;
        Ok(Box::new(RedbWrite(txn)))
    }
}

// ---------------------------------------------------------------------------------------------
// Typed rows.
// ---------------------------------------------------------------------------------------------

/// `meta` entries (§6.1, §19.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetaKey {
    SchemaVersion,
    /// Highest subaddress minor ever taken from the wallet (pool refill, reconciliation).
    HighestMinor,
    /// Heights up to this one were counted for unattributed revenue (§7.3).
    ScanFinalHeight,
    /// The treasury wallet's restore height (runbook R5; recorded by the Monero adapter, S5).
    RestoreHeight,
    /// Highest ES seq accepted (rule 5).
    EsSeq,
    /// Last journal sequence number applied to this database (§6.3).
    JournalApplied,
    /// Invite nullifiers of epochs <= this one were deleted; such tokens are refused (§19.10).
    ClosedThroughInviteEpoch,
    /// Credit nullifiers of epochs <= this one were deleted; such tokens are refused (§19.10).
    ClosedThroughCreditEpoch,
}

impl MetaKey {
    pub fn name(self) -> &'static str {
        match self {
            MetaKey::SchemaVersion => "schema_version",
            MetaKey::HighestMinor => "highest_minor",
            MetaKey::ScanFinalHeight => "scan_final_height",
            MetaKey::RestoreHeight => "restore_height",
            MetaKey::EsSeq => "es_seq",
            MetaKey::JournalApplied => "journal_applied",
            MetaKey::ClosedThroughInviteEpoch => "closed_through_invite_epoch",
            MetaKey::ClosedThroughCreditEpoch => "closed_through_credit_epoch",
        }
    }
}

pub fn meta(tx: &dyn ReadTx, key: MetaKey) -> Result<Option<u64>, StoreError> {
    tx.get(Table::Meta, key.name().as_bytes())?
        .map(|v| be_u64(&v))
        .transpose()
}

pub fn set_meta(tx: &mut dyn WriteTx, key: MetaKey, value: u64) -> Result<(), StoreError> {
    tx.put(Table::Meta, key.name().as_bytes(), &value.to_be_bytes())
}

/// Invoice states stored in `invoice.state` (§5.4). UNDERPAID and the AWAITING states are reported
/// states derived from the amounts, never stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvoiceState {
    Created,
    Seen,
    Confirmed,
    Issued,
    Expired,
}

impl InvoiceState {
    fn code(self) -> u8 {
        match self {
            InvoiceState::Created => 1,
            InvoiceState::Seen => 2,
            InvoiceState::Confirmed => 3,
            InvoiceState::Issued => 4,
            InvoiceState::Expired => 5,
        }
    }

    fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            1 => InvoiceState::Created,
            2 => InvoiceState::Seen,
            3 => InvoiceState::Confirmed,
            4 => InvoiceState::Issued,
            5 => InvoiceState::Expired,
            _ => return None,
        })
    }

    /// CREATED, SEEN, CONFIRMED or ISSUED: the invoice may still be served, so the keys of its
    /// layout stay loaded (§19.1).
    pub fn is_open(self) -> bool {
        !matches!(self, InvoiceState::Expired)
    }
}

/// How an invoice is paid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayWith {
    Monero,
    Credits,
}

impl PayWith {
    pub fn code(self) -> u8 {
        match self {
            PayWith::Monero => 1,
            PayWith::Credits => 2,
        }
    }

    pub fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(PayWith::Monero),
            2 => Some(PayWith::Credits),
            _ => None,
        }
    }
}

/// A row of `invoice` (§6.1, plus the subaddress). Heights only, no wall-clock time. A height of
/// 0 in `confirmed_height` or `issued_height` means "not stamped yet": the next scanner tick
/// stamps it with the wallet height (credits-paid invoices and journal replays know no height).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceRow {
    pub state: InvoiceState,
    pub pay_with: PayWith,
    /// 0 for a credits-paid invoice (minor 0 is never handed out).
    pub minor: u32,
    pub amount: u64,
    pub claim_hash: [u8; 32],
    /// R, the `RequestInvoice` idempotency digest.
    pub request_digest: [u8; 32],
    pub base_week: u64,
    pub es_seq: u64,
    pub created_height: u64,
    pub seen_deadline: u64,
    pub grace_height: u64,
    pub confirmed_height: u64,
    pub credited: u64,
    pub seen: u64,
    /// D of the served `BlindSign` request (ISSUED only).
    pub issued_digest: Option<[u8; 32]>,
    pub issued_height: u64,
    pub purge_height: u64,
    /// The invoice's subaddress (all zero bytes for a credits-paid invoice).
    pub subaddress: [u8; ADDRESS_LEN],
}

const INVOICE_ROW_LEN: usize = 1 + 1 + 4 + 8 + 32 + 32 + 8 * 8 + 32 + 8 + 8 + ADDRESS_LEN;

impl InvoiceRow {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(INVOICE_ROW_LEN);
        w.push(self.state.code());
        w.push(self.pay_with.code());
        w.extend_from_slice(&self.minor.to_be_bytes());
        w.extend_from_slice(&self.amount.to_be_bytes());
        w.extend_from_slice(&self.claim_hash);
        w.extend_from_slice(&self.request_digest);
        for v in [
            self.base_week,
            self.es_seq,
            self.created_height,
            self.seen_deadline,
            self.grace_height,
            self.confirmed_height,
            self.credited,
            self.seen,
        ] {
            w.extend_from_slice(&v.to_be_bytes());
        }
        w.extend_from_slice(&self.issued_digest.unwrap_or([0; 32]));
        w.extend_from_slice(&self.issued_height.to_be_bytes());
        w.extend_from_slice(&self.purge_height.to_be_bytes());
        w.extend_from_slice(&self.subaddress);
        w
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() != INVOICE_ROW_LEN {
            return Err(StoreError::Corrupt);
        }
        let mut r = Cursor(bytes);
        let state = InvoiceState::from_code(r.u8()?).ok_or(StoreError::Corrupt)?;
        let pay_with = PayWith::from_code(r.u8()?).ok_or(StoreError::Corrupt)?;
        let minor = r.u32()?;
        let amount = r.u64()?;
        let claim_hash = r.array()?;
        let request_digest = r.array()?;
        let base_week = r.u64()?;
        let es_seq = r.u64()?;
        let created_height = r.u64()?;
        let seen_deadline = r.u64()?;
        let grace_height = r.u64()?;
        let confirmed_height = r.u64()?;
        let credited = r.u64()?;
        let seen = r.u64()?;
        let digest: [u8; 32] = r.array()?;
        let issued_height = r.u64()?;
        let purge_height = r.u64()?;
        let subaddress = r.array()?;
        Ok(Self {
            state,
            pay_with,
            minor,
            amount,
            claim_hash,
            request_digest,
            base_week,
            es_seq,
            created_height,
            seen_deadline,
            grace_height,
            confirmed_height,
            credited,
            seen,
            issued_digest: (digest != [0; 32]).then_some(digest),
            issued_height,
            purge_height,
            subaddress,
        })
    }

    /// The subaddress text, or `""` for a credits-paid invoice.
    pub fn subaddress_text(&self) -> &str {
        if self.subaddress == [0; ADDRESS_LEN] {
            ""
        } else {
            std::str::from_utf8(&self.subaddress).unwrap_or("")
        }
    }
}

pub fn invoice(tx: &dyn ReadTx, id: &[u8; 16]) -> Result<Option<InvoiceRow>, StoreError> {
    tx.get(Table::Invoice, id)?
        .map(|v| InvoiceRow::decode(&v))
        .transpose()
}

pub fn put_invoice(
    tx: &mut dyn WriteTx,
    id: &[u8; 16],
    row: &InvoiceRow,
) -> Result<(), StoreError> {
    tx.put(Table::Invoice, id, &row.encode())
}

/// Every invoice, in id order.
pub fn invoices(tx: &dyn ReadTx) -> Result<Vec<([u8; 16], InvoiceRow)>, StoreError> {
    tx.range(Table::Invoice, &[], None)?
        .into_iter()
        .map(|(k, v)| Ok((array(&k)?, InvoiceRow::decode(&v)?)))
        .collect()
}

pub fn claim_index(tx: &dyn ReadTx, hash: &[u8; 32]) -> Result<Option<[u8; 16]>, StoreError> {
    tx.get(Table::ClaimIndex, hash)?
        .map(|v| array(&v))
        .transpose()
}

pub fn minor_index(tx: &dyn ReadTx, minor: u32) -> Result<Option<[u8; 16]>, StoreError> {
    tx.get(Table::MinorIndex, &minor.to_be_bytes())?
        .map(|v| array(&v))
        .transpose()
}

/// The lowest-minor pool entry.
pub fn pool_first(tx: &dyn ReadTx) -> Result<Option<(u32, [u8; ADDRESS_LEN])>, StoreError> {
    Ok(pool(tx)?.into_iter().next())
}

/// Every pool entry, ascending by minor.
pub fn pool(tx: &dyn ReadTx) -> Result<Vec<(u32, [u8; ADDRESS_LEN])>, StoreError> {
    tx.range(Table::AddressPool, &[], None)?
        .into_iter()
        .map(|(k, v)| Ok((be_u32(&k)?, array(&v)?)))
        .collect()
}

/// The txids credited to an invoice with the height they were credited at.
pub fn credited_txs(tx: &dyn ReadTx, id: &[u8; 16]) -> Result<Vec<([u8; 32], u64)>, StoreError> {
    let mut end = *id;
    let start = id.to_vec();
    // The first key after every `id || txid` is `id + 1` (ids are fixed-length byte strings).
    let end = increment(&mut end).then(|| end.to_vec());
    tx.range(Table::CreditedTx, &start, end.as_deref())?
        .into_iter()
        .map(|(k, v)| Ok((array(&k[16..])?, be_u64(&v)?)))
        .collect()
}

pub fn credited_key(id: &[u8; 16], txid: &[u8; 32]) -> [u8; 48] {
    let mut k = [0u8; 48];
    k[..16].copy_from_slice(id);
    k[16..].copy_from_slice(txid);
    k
}

/// `epoch u64 || N`: the key of both nullifier tables.
pub fn nullifier_key(epoch: u64, nullifier: &[u8; 32]) -> [u8; 40] {
    let mut k = [0u8; 40];
    k[..8].copy_from_slice(&epoch.to_be_bytes());
    k[8..].copy_from_slice(nullifier);
    k
}

pub fn invite_nullifier(
    tx: &dyn ReadTx,
    epoch: u64,
    nullifier: &[u8; 32],
) -> Result<Option<[u8; 32]>, StoreError> {
    tx.get(Table::InviteNullifier, &nullifier_key(epoch, nullifier))?
        .map(|v| array(&v))
        .transpose()
}

/// What a credit was used for (`credit_nullifier.use`, §6.1). Only a refresh keeps a reference,
/// the first 16 bytes of its blinded digest (its idempotent re-serve compares it, §5.6). A
/// discount or a payout keeps none: the nullifier outlives the invoice (≈ 7 days after issuance)
/// and the claim (batch paid + 7 days) by up to 65 weeks, and a reference would keep the set of
/// credits presented together, a purchase-cadence fingerprint (§19.1 rule 5), for that long.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CreditUse {
    Discount,
    Payout,
    Refresh([u8; 16]),
}

impl CreditUse {
    pub fn encode(&self) -> [u8; 17] {
        let mut out = [0u8; 17];
        match self {
            CreditUse::Discount => out[0] = 1,
            CreditUse::Payout => out[0] = 2,
            CreditUse::Refresh(r) => {
                out[0] = 3;
                out[1..].copy_from_slice(r);
            }
        }
        out
    }

    /// Strict: a discount or payout row with a non-zero reference does not decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() != 17 {
            return Err(StoreError::Corrupt);
        }
        let reference: [u8; 16] = array(&bytes[1..])?;
        Ok(match (bytes[0], reference == [0; 16]) {
            (1, true) => CreditUse::Discount,
            (2, true) => CreditUse::Payout,
            (3, _) => CreditUse::Refresh(reference),
            _ => return Err(StoreError::Corrupt),
        })
    }
}

pub fn credit_nullifier(
    tx: &dyn ReadTx,
    epoch: u64,
    nullifier: &[u8; 32],
) -> Result<Option<CreditUse>, StoreError> {
    tx.get(Table::CreditNullifier, &nullifier_key(epoch, nullifier))?
        .map(|v| CreditUse::decode(&v))
        .transpose()
}

/// `claim.state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimState {
    /// Accepted, waiting for the weekly batch.
    Queued,
    /// Assigned to a batch (journaled `BATCH`).
    Batched,
    /// Its batch was paid (journaled `BATCH_PAID`); the payout address is deleted.
    Paid,
}

/// A row of `claim` (§6.1; no time column, §19.15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRow {
    pub state: ClaimState,
    pub amount: u64,
    pub credits: u8,
    /// The body digest of the `ClaimPayout` request (idempotency, §5.6).
    pub digest: [u8; 32],
    pub address: [u8; ADDRESS_LEN],
    pub batch_id: [u8; 16],
}

const CLAIM_ROW_LEN: usize = 1 + 8 + 1 + 32 + ADDRESS_LEN + 16;

impl ClaimRow {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(CLAIM_ROW_LEN);
        w.push(match self.state {
            ClaimState::Queued => 1,
            ClaimState::Batched => 2,
            ClaimState::Paid => 3,
        });
        w.extend_from_slice(&self.amount.to_be_bytes());
        w.push(self.credits);
        w.extend_from_slice(&self.digest);
        w.extend_from_slice(&self.address);
        w.extend_from_slice(&self.batch_id);
        w
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() != CLAIM_ROW_LEN {
            return Err(StoreError::Corrupt);
        }
        let mut r = Cursor(bytes);
        let state = match r.u8()? {
            1 => ClaimState::Queued,
            2 => ClaimState::Batched,
            3 => ClaimState::Paid,
            _ => return Err(StoreError::Corrupt),
        };
        Ok(Self {
            state,
            amount: r.u64()?,
            credits: r.u8()?,
            digest: r.array()?,
            address: r.array()?,
            batch_id: r.array()?,
        })
    }
}

pub fn claim(tx: &dyn ReadTx, id: &[u8; 16]) -> Result<Option<ClaimRow>, StoreError> {
    tx.get(Table::Claim, id)?
        .map(|v| ClaimRow::decode(&v))
        .transpose()
}

/// Every claim, in id order.
pub fn claims(tx: &dyn ReadTx) -> Result<Vec<([u8; 16], ClaimRow)>, StoreError> {
    tx.range(Table::Claim, &[], None)?
        .into_iter()
        .map(|(k, v)| Ok((array(&k)?, ClaimRow::decode(&v)?)))
        .collect()
}

pub fn put_claim(tx: &mut dyn WriteTx, id: &[u8; 16], row: &ClaimRow) -> Result<(), StoreError> {
    tx.put(Table::Claim, id, &row.encode())
}

/// `batch.state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BatchState {
    /// Written to the export directory, waiting for the workstation's acknowledgement.
    Exported,
    /// Every entry was acknowledged.
    Paid,
}

/// A row of `batch` (§6.1 plus `cumulative_credited` and `paid_week`; weeks only, §19.15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchRow {
    pub state: BatchState,
    /// The week the batch was created in.
    pub week: u64,
    /// Σ amounts of its claims.
    pub total: u64,
    pub entries: u16,
    pub cumulative_credited: u64,
    /// The week of the acknowledgement (0 while exported).
    pub paid_week: u64,
}

const BATCH_ROW_LEN: usize = 1 + 8 + 8 + 2 + 8 + 8;

impl BatchRow {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(BATCH_ROW_LEN);
        w.push(match self.state {
            BatchState::Exported => 1,
            BatchState::Paid => 2,
        });
        w.extend_from_slice(&self.week.to_be_bytes());
        w.extend_from_slice(&self.total.to_be_bytes());
        w.extend_from_slice(&self.entries.to_be_bytes());
        w.extend_from_slice(&self.cumulative_credited.to_be_bytes());
        w.extend_from_slice(&self.paid_week.to_be_bytes());
        w
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() != BATCH_ROW_LEN {
            return Err(StoreError::Corrupt);
        }
        let mut r = Cursor(bytes);
        let state = match r.u8()? {
            1 => BatchState::Exported,
            2 => BatchState::Paid,
            _ => return Err(StoreError::Corrupt),
        };
        Ok(Self {
            state,
            week: r.u64()?,
            total: r.u64()?,
            entries: u16::from_be_bytes(r.array()?),
            cumulative_credited: r.u64()?,
            paid_week: r.u64()?,
        })
    }
}

pub fn batch(tx: &dyn ReadTx, id: &[u8; 16]) -> Result<Option<BatchRow>, StoreError> {
    tx.get(Table::Batch, id)?
        .map(|v| BatchRow::decode(&v))
        .transpose()
}

pub fn put_batch(tx: &mut dyn WriteTx, id: &[u8; 16], row: &BatchRow) -> Result<(), StoreError> {
    tx.put(Table::Batch, id, &row.encode())
}

/// Every batch, in id order.
pub fn batches(tx: &dyn ReadTx) -> Result<Vec<([u8; 16], BatchRow)>, StoreError> {
    tx.range(Table::Batch, &[], None)?
        .into_iter()
        .map(|(k, v)| Ok((array(&k)?, BatchRow::decode(&v)?)))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Encoding helpers.
// ---------------------------------------------------------------------------------------------

pub(crate) fn be_u64(bytes: &[u8]) -> Result<u64, StoreError> {
    Ok(u64::from_be_bytes(array(bytes)?))
}

pub(crate) fn be_u32(bytes: &[u8]) -> Result<u32, StoreError> {
    Ok(u32::from_be_bytes(array(bytes)?))
}

pub(crate) fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::Corrupt)
}

/// Adds one to a big-endian byte string; false on overflow (all bytes 0xFF).
fn increment(bytes: &mut [u8]) -> bool {
    for b in bytes.iter_mut().rev() {
        if *b == 0xFF {
            *b = 0;
        } else {
            *b += 1;
            return true;
        }
    }
    false
}

struct Cursor<'a>(&'a [u8]);

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], StoreError> {
        if self.0.len() < n {
            return Err(StoreError::Corrupt);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, StoreError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        be_u32(self.take(4)?)
    }

    fn u64(&mut self) -> Result<u64, StoreError> {
        be_u64(self.take(8)?)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StoreError> {
        array(self.take(N)?)
    }
}
