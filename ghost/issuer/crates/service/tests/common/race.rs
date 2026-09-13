//! Two concurrent requests for crash scenario I-K (Phase 8 design §13.2, §19.5): a store whose
//! first writer of an armed race holds its write transaction until the second writer has asked
//! for one. Both requests have then passed every check before either transaction commits, so one
//! wins inside its transaction and the other must lose its re-check (decide, then journal: the
//! loser journals nothing).

use std::sync::{Condvar, Mutex};
use std::time::Duration;

use ghost_issuer::store::{ReadTx, RedbStore, Store, StoreError, WriteTx};

#[derive(Default)]
struct State {
    armed: bool,
    /// `write` calls since the race was armed.
    writers: usize,
}

/// The ordering of one race.
#[derive(Default)]
pub struct Gate {
    state: Mutex<State>,
    cv: Condvar,
}

impl Gate {
    pub fn arm(&self) {
        self.state.lock().unwrap().armed = true;
    }

    /// How many writers asked for a transaction since the race was armed.
    pub fn writers(&self) -> usize {
        self.state.lock().unwrap().writers
    }
}

pub struct RaceStore {
    pub inner: RedbStore,
    pub gate: std::sync::Arc<Gate>,
}

impl Store for RaceStore {
    fn read(&self) -> Result<Box<dyn ReadTx + '_>, StoreError> {
        self.inner.read()
    }

    fn write(&self) -> Result<Box<dyn WriteTx + '_>, StoreError> {
        let order = {
            let mut s = self.gate.state.lock().unwrap();
            if s.armed {
                s.writers += 1;
                s.writers
            } else {
                0
            }
        };
        self.gate.cv.notify_all();
        let tx = self.inner.write()?;
        if order == 1 {
            let guard = self.gate.state.lock().unwrap();
            let (_guard, timeout) = self
                .gate
                .cv
                .wait_timeout_while(guard, Duration::from_secs(60), |s| s.writers < 2)
                .unwrap();
            assert!(
                !timeout.timed_out(),
                "I-K: the second request never reached its transaction"
            );
        }
        Ok(tx)
    }
}
