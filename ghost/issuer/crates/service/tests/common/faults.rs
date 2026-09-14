//! Fault injection for the issuer crash harness (Phase 8 design §13.2, G-10): `FaultyStore` (an
//! event before every write transaction, pre-commit, post-commit), `FaultyJournal` (before fsync:
//! the entry is lost; a torn last record; after fsync) and `FaultyRail` (before the call, after
//! its effect but before the response). A fault answers the issuer with an error; the harness
//! then drops every in-memory object and reopens the same files, exactly as after a crash.

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ghost_issuer::journal::{Entry, FileJournal, Journal, JournalError};
use ghost_issuer::rail::{IncomingEntry, PaymentRail, RailError, RailHeight};
use ghost_issuer::store::{ReadTx, RedbStore, Rows, Store, StoreError, Table, WriteTx};

use super::chain_port::ChainPort;

/// A fault site: one call at a port boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Site {
    StoreBegin,
    StoreCommit,
    Journal,
    Rail,
}

/// What a fault does at its site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// The write transaction never begins.
    BeforeTxn,
    /// The transaction is dropped instead of committed.
    PreCommit,
    /// The transaction commits, then the process dies.
    PostCommit,
    /// The entry never reaches the disk (crash before fsync).
    JournalLost,
    /// Half the entry reaches the disk (a torn last record).
    JournalTorn,
    /// The entry is durable, then the process dies (between fsync and commit).
    JournalDurable,
    /// The rail call never happens.
    RailBefore,
    /// The rail call takes effect, the answer is lost.
    RailAfter,
}

impl Site {
    pub fn modes(self) -> &'static [Mode] {
        match self {
            Site::StoreBegin => &[Mode::BeforeTxn],
            Site::StoreCommit => &[Mode::PreCommit, Mode::PostCommit],
            Site::Journal => &[Mode::JournalLost, Mode::JournalTorn, Mode::JournalDurable],
            Site::Rail => &[Mode::RailBefore, Mode::RailAfter],
        }
    }
}

/// A transaction another task commits on the database while a handler is between two of its
/// store calls (the interleaving of a concurrent sweep, §19.10). It runs on the inner store, so
/// it is neither a fault site nor counted.
pub type StoreHook = Box<dyn FnOnce(&RedbStore) + Send>;

/// Which store call a [`StoreHook`] precedes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookAt {
    Read,
    Write,
}

struct PendingHook {
    at: HookAt,
    /// Calls of that kind still to pass before the hook runs.
    skip: usize,
    hook: StoreHook,
}

/// Which fault sites fire. Sites are numbered from 0 in the order they are reached after `arm`.
pub struct FaultPlan {
    armed: AtomicBool,
    index: AtomicUsize,
    targets: Vec<(usize, Mode)>,
    sites: Mutex<Vec<Site>>,
    fired: AtomicUsize,
    pending: AtomicBool,
    hook: Mutex<Option<PendingHook>>,
}

impl FaultPlan {
    pub fn new(targets: Vec<(usize, Mode)>) -> Arc<Self> {
        Arc::new(Self {
            armed: AtomicBool::new(false),
            index: AtomicUsize::new(0),
            targets,
            sites: Mutex::new(Vec::new()),
            fired: AtomicUsize::new(0),
            pending: AtomicBool::new(false),
            hook: Mutex::new(None),
        })
    }

    /// Runs `hook` on the database right before the `n`-th (from 1) store call of kind `at` made
    /// after this call.
    pub fn before(&self, at: HookAt, n: usize, hook: StoreHook) {
        assert!(n >= 1);
        *self.hook.lock().unwrap() = Some(PendingHook {
            at,
            skip: n - 1,
            hook,
        });
    }

    /// True once the hook installed by [`FaultPlan::before`] has run.
    pub fn hook_ran(&self) -> bool {
        self.hook.lock().unwrap().is_none()
    }

    fn run_hook(&self, at: HookAt, db: &RedbStore) {
        let hook = {
            let mut slot = self.hook.lock().unwrap();
            match slot.as_mut() {
                Some(p) if p.at == at && p.skip > 0 => {
                    p.skip -= 1;
                    None
                }
                Some(p) if p.at == at => slot.take().map(|p| p.hook),
                _ => None,
            }
        };
        if let Some(hook) = hook {
            hook(db);
        }
    }

    pub fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    fn hit(&self, site: Site) -> Option<Mode> {
        if !self.armed.load(Ordering::SeqCst) {
            return None;
        }
        let i = self.index.fetch_add(1, Ordering::SeqCst);
        self.sites.lock().unwrap().push(site);
        let mode = self
            .targets
            .iter()
            .find(|(t, m)| *t == i && site.modes().contains(m))
            .map(|(_, m)| *m)?;
        self.fired.fetch_add(1, Ordering::SeqCst);
        self.pending.store(true, Ordering::SeqCst);
        Some(mode)
    }

    /// True once after every fault that fired: the harness crashes the issuer.
    pub fn take_crash(&self) -> bool {
        self.pending.swap(false, Ordering::SeqCst)
    }

    pub fn fired(&self) -> usize {
        self.fired.load(Ordering::SeqCst)
    }

    pub fn sites(&self) -> Vec<Site> {
        self.sites.lock().unwrap().clone()
    }
}

pub struct FaultyStore {
    pub inner: RedbStore,
    pub plan: Arc<FaultPlan>,
}

struct FaultyWrite<'a> {
    inner: Box<dyn WriteTx + 'a>,
    plan: &'a FaultPlan,
}

impl ReadTx for FaultyWrite<'_> {
    fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.get(table, key)
    }
    fn range(&self, table: Table, start: &[u8], end: Option<&[u8]>) -> Result<Rows, StoreError> {
        self.inner.range(table, start, end)
    }
}

impl WriteTx for FaultyWrite<'_> {
    fn put(&mut self, table: Table, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.inner.put(table, key, value)
    }
    fn delete(&mut self, table: Table, key: &[u8]) -> Result<(), StoreError> {
        self.inner.delete(table, key)
    }
    fn commit(self: Box<Self>) -> Result<(), StoreError> {
        match self.plan.hit(Site::StoreCommit) {
            Some(Mode::PreCommit) => Err(StoreError::Db),
            Some(_) => {
                self.inner.commit()?;
                Err(StoreError::Db)
            }
            None => self.inner.commit(),
        }
    }
}

impl Store for FaultyStore {
    fn read(&self) -> Result<Box<dyn ReadTx + '_>, StoreError> {
        self.plan.run_hook(HookAt::Read, &self.inner);
        self.inner.read()
    }
    fn write(&self) -> Result<Box<dyn WriteTx + '_>, StoreError> {
        self.plan.run_hook(HookAt::Write, &self.inner);
        if self.plan.hit(Site::StoreBegin).is_some() {
            return Err(StoreError::Db);
        }
        Ok(Box::new(FaultyWrite {
            inner: self.inner.write()?,
            plan: &self.plan,
        }))
    }
}

pub struct FaultyJournal {
    pub inner: FileJournal,
    pub plan: Arc<FaultPlan>,
}

impl Journal for FaultyJournal {
    fn entries(&self) -> Result<Vec<(u64, Entry)>, JournalError> {
        self.inner.entries()
    }
    fn append(&self, week: u64, entry: &Entry) -> Result<u64, JournalError> {
        match self.plan.hit(Site::Journal) {
            Some(Mode::JournalLost) => Err(JournalError::Io),
            Some(Mode::JournalTorn) => {
                let (path, seq) = self.inner.next(week);
                let frame = entry.encode(seq)?;
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|_| JournalError::Io)?;
                file.write_all(&frame[..frame.len() / 2])
                    .and_then(|()| file.sync_data())
                    .map_err(|_| JournalError::Io)?;
                Err(JournalError::Io)
            }
            Some(_) => {
                self.inner.append(week, entry)?;
                Err(JournalError::Io)
            }
            None => self.inner.append(week, entry),
        }
    }
    fn next_seq(&self) -> Result<u64, JournalError> {
        self.inner.next_seq()
    }
    fn last_entry_week(&self) -> Option<u64> {
        self.inner.last_entry_week()
    }
}

pub struct FaultyRail {
    pub inner: Arc<ChainPort>,
    pub plan: Arc<FaultPlan>,
}

impl FaultyRail {
    fn call<T>(&self, f: impl FnOnce(&ChainPort) -> Result<T, RailError>) -> Result<T, RailError> {
        match self.plan.hit(Site::Rail) {
            Some(Mode::RailBefore) => Err(RailError::Transport),
            Some(_) => {
                let _ = f(&self.inner);
                Err(RailError::Transport)
            }
            None => f(&self.inner),
        }
    }
}

impl PaymentRail for FaultyRail {
    fn new_address(&self) -> Result<(u32, String), RailError> {
        self.call(|c| c.new_address())
    }
    fn address_count(&self) -> Result<u32, RailError> {
        self.call(|c| c.address_count())
    }
    fn height(&self) -> Result<RailHeight, RailError> {
        self.call(|c| c.height())
    }
    fn transfers(&self, from: u64, to: u64) -> Result<Vec<IncomingEntry>, RailError> {
        self.call(|c| c.transfers(from, to))
    }
    fn transfer_by_txid(&self, txid: &[u8; 32]) -> Result<Option<IncomingEntry>, RailError> {
        self.call(|c| c.transfer_by_txid(txid))
    }
}
