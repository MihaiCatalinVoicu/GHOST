//! Decide-then-journal under concurrency (Phase 8 design §6.2, §6.3, §19.5 rule 2, §19.10): what a
//! handler already past its entry checks may do when the writer before it failed, or when a sweep
//! commits between its checks and its transaction.
//!
//! - A failed journal append or commit halts the issuer. A handler queued behind the failed writer
//!   on the store's one write transaction must not decide after it: it answers `UNAVAILABLE`,
//!   journals nothing, and the journal still opens and replays every decided entry at the restart
//!   (journal order equals commit order).
//! - A sweep that closes a credit or invite epoch between a handler's closed-through read and its
//!   transaction: the transaction re-reads the high-water mark, so a closed epoch is refused
//!   whatever was read before (MS-3).

mod common;

use std::io::Write;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use common::chain_port::{self, RailHandle};
use common::faults::{HookAt, StoreHook};
use common::world::{harness_params, World, BASE_WEEK};
use ghost_entitlement::grid::{invite_epoch, week_start};
use ghost_entitlement::{Kind, Token};
use ghost_issuer::journal::{Entry, FileJournal, Journal, JournalError};
use ghost_issuer::service::{Issuer, OpenMode, OsRandom, Ports};
use ghost_issuer::store::{
    self, MetaKey, ReadTx, RedbStore, Rows, Store, StoreError, Table, WriteTx,
};
use ghost_issuer_api::proto as wire;
use tonic::Code;

const INVITE_OK: i32 = wire::RedeemInviteResult::Ok as i32;
const QUEUED: i32 = wire::ClaimPayoutResult::Queued as i32;

// ------------------------------------------------------------------------------------------------
// Two writers, the first one fails.
// ------------------------------------------------------------------------------------------------

#[derive(Default)]
struct RaceState {
    armed: bool,
    /// `write` calls since arming; the first caller is "the first writer".
    writers: usize,
    first_holds: bool,
    /// Handler calls that returned.
    answered: usize,
    /// The first append tears half a frame into the segment and fails.
    tear_first_append: bool,
    /// The first writer's commit releases its transaction uncommitted and fails, once the other
    /// call has answered.
    fail_first_commit: bool,
}

#[derive(Default)]
struct Race {
    state: Mutex<RaceState>,
    cv: Condvar,
}

impl Race {
    fn update(&self, f: impl FnOnce(&mut RaceState)) {
        f(&mut self.state.lock().unwrap());
        self.cv.notify_all();
    }

    fn wait(&self, what: &str, until: impl Fn(&RaceState) -> bool) {
        let guard = self.state.lock().unwrap();
        let (_guard, timeout) = self
            .cv
            .wait_timeout_while(guard, Duration::from_secs(60), |s| !until(s))
            .unwrap();
        assert!(!timeout.timed_out(), "race: timed out waiting for {what}");
    }
}

/// Orders two concurrent writers: the first to ask for a write transaction gets it, the second
/// waits until the first holds it and then queues on the store's one writer.
struct GateStore {
    inner: RedbStore,
    race: Arc<Race>,
}

struct GateWrite<'a> {
    inner: Box<dyn WriteTx + 'a>,
    race: &'a Race,
    first: bool,
}

impl ReadTx for GateWrite<'_> {
    fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.get(table, key)
    }
    fn range(&self, table: Table, start: &[u8], end: Option<&[u8]>) -> Result<Rows, StoreError> {
        self.inner.range(table, start, end)
    }
}

impl WriteTx for GateWrite<'_> {
    fn put(&mut self, table: Table, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.inner.put(table, key, value)
    }
    fn delete(&mut self, table: Table, key: &[u8]) -> Result<(), StoreError> {
        self.inner.delete(table, key)
    }
    fn commit(self: Box<Self>) -> Result<(), StoreError> {
        let fail = self.first && self.race.state.lock().unwrap().fail_first_commit;
        if !fail {
            return self.inner.commit();
        }
        let GateWrite { inner, race, .. } = *self;
        // The transaction is released without committing (redb frees the writer when a failed
        // commit returns); the error reaches the issuer only after the other call answered.
        drop(inner);
        race.wait("the other call's answer", |s| s.answered >= 1);
        Err(StoreError::Db)
    }
}

impl Store for GateStore {
    fn read(&self) -> Result<Box<dyn ReadTx + '_>, StoreError> {
        self.inner.read()
    }
    fn write(&self) -> Result<Box<dyn WriteTx + '_>, StoreError> {
        let order = {
            let mut s = self.race.state.lock().unwrap();
            if s.armed {
                s.writers += 1;
            }
            if s.armed {
                s.writers
            } else {
                0
            }
        };
        self.race.cv.notify_all();
        if order >= 2 {
            self.race
                .wait("the first writer's transaction", |s| s.first_holds);
        }
        let inner = self.inner.write()?;
        if order == 1 {
            self.race.update(|s| s.first_holds = true);
        }
        Ok(Box::new(GateWrite {
            inner,
            race: &self.race,
            first: order == 1,
        }))
    }
}

/// The journal of the race: optionally the first append, made once the second writer queues,
/// leaves half a frame in the segment and fails (a write error after a partial write).
struct TearingJournal {
    inner: FileJournal,
    race: Arc<Race>,
}

impl Journal for TearingJournal {
    fn entries(&self) -> Result<Vec<(u64, Entry)>, JournalError> {
        self.inner.entries()
    }
    fn append(&self, week: u64, entry: &Entry) -> Result<u64, JournalError> {
        let tear = {
            let mut s = self.race.state.lock().unwrap();
            let tear = s.armed && s.tear_first_append;
            s.tear_first_append = false;
            tear
        };
        if !tear {
            return self.inner.append(week, entry);
        }
        self.race.wait("the second writer", |s| s.writers >= 2);
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
    fn next_seq(&self) -> Result<u64, JournalError> {
        self.inner.next_seq()
    }
    fn last_entry_week(&self) -> Option<u64> {
        self.inner.last_entry_week()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    TornAppend,
    FailedCommit,
}

/// Two new trials redeemed concurrently while the first writer fails; then a restart on the same
/// files and the identical retries.
fn race_two_trials(failure: Failure) {
    let mut w = World::new(true);
    let e = invite_epoch(BASE_WEEK);
    let invites: Vec<Token> = ["race-a", "race-b"]
        .iter()
        .map(|l| w.mint(Kind::Invite, e, l))
        .collect();
    let trials: Vec<Vec<u8>> = ["race-ta", "race-tb"]
        .iter()
        .map(|l| w.trial_blinded(l, BASE_WEEK))
        .collect();
    w.crash();
    let race = Arc::new(Race::default());
    let dir = w.dir.path().to_path_buf();
    let issuer = Issuer::open(
        w.schedule.clone(),
        w.keys.clone(),
        Ports {
            store: Box::new(GateStore {
                inner: RedbStore::open(&dir.join("issuer.redb")).unwrap(),
                race: Arc::clone(&race),
            }),
            journal: Box::new(TearingJournal {
                inner: FileJournal::open(&dir.join("journal")).unwrap(),
                race: Arc::clone(&race),
            }),
            rail: Box::new(RailHandle(Arc::clone(&w.chain))),
            random: Box::new(OsRandom::new()),
        },
        harness_params(),
        OpenMode::Normal,
        w.now,
    )
    .unwrap();
    race.update(|s| {
        s.armed = true;
        s.tear_first_append = failure == Failure::TornAppend;
        s.fail_first_commit = failure == Failure::FailedCommit;
    });
    let now = w.now;
    let results: Vec<Result<wire::RedeemInviteResponse, tonic::Status>> =
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|i| {
                    let req = wire::RedeemInviteRequest {
                        version: 1,
                        invite_token: invites[i].as_bytes().to_vec(),
                        base_week: BASE_WEEK,
                        blinded: trials[i].clone(),
                    };
                    let (issuer, race) = (&issuer, &race);
                    scope.spawn(move || {
                        let r = issuer.redeem_invite_at(req, now);
                        race.update(|s| s.answered += 1);
                        r
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
    assert!(issuer.is_halted(), "{failure:?}: the issuer did not halt");
    for r in &results {
        match r {
            Err(status) => assert_eq!(status.code(), Code::Unavailable, "{failure:?}"),
            Ok(answer) => panic!(
                "{failure:?}: a queued writer decided after the failed one (result {})",
                answer.result
            ),
        }
    }
    drop(issuer);

    // The restart: the journal opens (a torn tail is discarded), every entry is replayed.
    w.open(OpenMode::Normal);
    w.refill();
    w.tick();
    {
        let entries = FileJournal::open(&dir.join("journal"))
            .unwrap()
            .entries()
            .unwrap();
        let tx = w.issuer().store().read().unwrap();
        for (seq, entry) in entries {
            if let Entry::Invite {
                epoch,
                nullifier,
                digest,
                ..
            } = entry
            {
                assert_eq!(
                    store::invite_nullifier(&*tx, epoch, &nullifier).unwrap(),
                    Some(digest),
                    "{failure:?}: journal entry {seq} decided but never applied"
                );
            }
        }
    }
    // Both clients retry identically and are served.
    for (invite, trial) in invites.iter().zip(&trials) {
        assert_eq!(
            w.redeem(invite, BASE_WEEK, trial.clone()).unwrap().result,
            INVITE_OK
        );
    }
    w.check();
}

#[test]
fn a_torn_journal_append_halts_the_writer_queued_behind_it() {
    race_two_trials(Failure::TornAppend);
}

#[test]
fn a_failed_commit_halts_the_writer_queued_behind_it() {
    race_two_trials(Failure::FailedCommit);
}

// ------------------------------------------------------------------------------------------------
// A sweep between a handler's checks and its transaction.
// ------------------------------------------------------------------------------------------------

fn mint_many(w: &World, kind: Kind, epoch: u64, n: usize, tag: &str) -> Vec<Token> {
    (0..n)
        .map(|i| w.mint(kind, epoch, &format!("{tag}-{i}")))
        .collect()
}

/// The transaction `sweep_at` commits when credit epoch `through + 5` begins: the credit
/// nullifiers of epochs ≤ `through` are deleted and the closed-through mark is raised.
fn sweep_credit_epochs(through: u64) -> StoreHook {
    Box::new(move |db: &RedbStore| {
        let mut tx = db.write().unwrap();
        let end = (through + 1).to_be_bytes();
        for (k, _) in tx.range(Table::CreditNullifier, &[], Some(&end)).unwrap() {
            tx.delete(Table::CreditNullifier, &k).unwrap();
        }
        store::set_meta(&mut *tx, MetaKey::ClosedThroughCreditEpoch, through).unwrap();
        tx.commit().unwrap();
    })
}

/// The mark `sweep_at` raises when invite epoch `through + 2` begins.
fn close_invite_epochs(through: u64) -> StoreHook {
    Box::new(move |db: &RedbStore| {
        let mut tx = db.write().unwrap();
        store::set_meta(&mut *tx, MetaKey::ClosedThroughInviteEpoch, through).unwrap();
        tx.commit().unwrap();
    })
}

fn refused<T>(r: Result<T, tonic::Status>, what: &str, result: impl Fn(&T) -> i32) {
    match r {
        Err(status) => assert_eq!(status.code(), Code::PermissionDenied, "{what}"),
        Ok(answer) => panic!("{what}: accepted (result {})", result(&answer)),
    }
}

/// `ClaimPayout` in the last minute of credit epoch 231 with ten credits of epoch 227 (the oldest
/// accepted), already spent by another claim. The sweep of epoch 232 lands between the handler's
/// closed-through read (its second store read) and its spent check (the third).
#[test]
fn a_sweep_between_the_checks_and_the_transaction_cannot_reopen_spent_credits_for_a_claim() {
    let mut w = World::new(true);
    w.external_credits = true;
    w.now = week_start(232 * 13) - 60;
    let credits = mint_many(&w, Kind::Credit, 227, 10, "c");
    let address = chain_port::address(9_999);
    assert_eq!(w.claim("q", &credits, &address).unwrap().result, QUEUED);
    w.plan.before(HookAt::Read, 3, sweep_credit_epochs(227));
    let r = w.claim("q2", &credits, &address);
    assert!(w.plan.hook_ran());
    refused(r, "MS-3: spent credits of a closed epoch", |a| a.result);
}

/// The same interleaving for a credits-paid `RequestInvoice`. The harness ES ends at week 2982, so
/// the concurrent sweep here ran with a clock five credit epochs ahead of the handler's (a clock
/// step back is the other way this order of events arises, §19.10).
#[test]
fn a_sweep_between_the_checks_and_the_transaction_cannot_reopen_spent_credits_for_a_pack() {
    let mut w = World::new(true);
    w.external_credits = true;
    let credits = mint_many(&w, Kind::Credit, 227, 10, "c");
    let address = chain_port::address(9_999);
    assert_eq!(w.claim("q", &credits, &address).unwrap().result, QUEUED);
    w.plan.before(HookAt::Read, 3, sweep_credit_epochs(227));
    let r = w.request("d", BASE_WEEK, &credits);
    assert!(w.plan.hook_ran());
    refused(r, "MS-3: spent credits of a closed epoch", |a| a.result);
}

/// `RedeemInvite` of a fresh invite of epoch 740 in the last minute of epoch 741: the sweep of
/// epoch 742 raises the closed-through mark after the handler's checks and before its
/// transaction; the transaction refuses the closed epoch (§19.10).
#[test]
fn a_sweep_between_the_checks_and_the_transaction_refuses_a_closed_invite_epoch() {
    let mut w = World::new(true);
    w.now = week_start(2968) - 60;
    let invite = w.mint(Kind::Invite, 740, "i");
    let trial = w.trial_blinded("t", 2967);
    w.plan.before(HookAt::Write, 1, close_invite_epochs(740));
    let r = w.redeem(&invite, 2967, trial);
    assert!(w.plan.hook_ran());
    refused(r, "a new redemption of a closed invite epoch", |a| a.result);
}
