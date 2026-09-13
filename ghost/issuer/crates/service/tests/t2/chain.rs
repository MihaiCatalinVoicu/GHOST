//! The T2 wallet (Phase 8 design §13.3 step 18, RP §6.8): a view-only Monero wallet over a block
//! schedule on the world clock, exposing exactly the `get_transfers` fields the issuer reads plus
//! the pool-first-seen `timestamp` (L6), which only the T2 wallet view uses. Every rail call and its
//! answer is logged for `wallet_view`.
//!
//! Blocks: block k (1-based after the start) is produced at `t0 + 120 k + jitter(k)`, jitter in
//! [0, 60) s from the chain seed. A transfer first seen at `t_s` is mined in the first block
//! produced after `t_s` plus `delay` whole blocks (0 unless a twin world shifts chain timing);
//! mined at count h, it has `B(t) − h` confirmations at time t, as the crash harness's `ChainPort`.

use std::sync::{Arc, Mutex};

use ghost_issuer::rail::{IncomingEntry, PaymentRail, RailError, RailHeight};

use super::rng::Rng;
use crate::common::chain_port::address;

pub const BLOCK_SECS: u64 = 120;
pub const START_BLOCKS: u64 = 1_000;

#[derive(Debug, Clone)]
pub struct ChainTx {
    pub txid: [u8; 32],
    pub minor: u32,
    pub amount: u64,
    pub first_seen: u64,
    /// The block index (1-based after the start) that mines it.
    pub block: u64,
}

/// One logged rail call: method, its arguments, and the answer.
#[derive(Debug, Clone)]
pub struct WalletLog {
    pub t: u64,
    pub method: &'static str,
    pub args: Vec<u64>,
    pub address: Option<String>,
    pub entries: Vec<IncomingEntry>,
    pub error: bool,
}

pub struct ChainState {
    t0: u64,
    jitter: Vec<u64>,
    pub now: u64,
    pub addresses: Vec<String>,
    pub txs: Vec<ChainTx>,
    next_txid: u64,
    txid_seed: u64,
    pub log: Vec<WalletLog>,
    pub failure: Option<RailError>,
}

pub struct T2Chain(Mutex<ChainState>);

impl T2Chain {
    /// A chain whose block times are the same in every world (twin worlds vary chain timing only
    /// through the mining delay of each payment, `pay`), with txids from `seed`.
    pub fn new(t0: u64, seed: u64) -> Arc<Self> {
        let mut rng = Rng::new(0x424c_4f43_4b53, &[b"blocks"]);
        let txid_seed = seed;
        // Enough jitter for 600 days of blocks, drawn once.
        let jitter = (0..600 * 720).map(|_| rng.below(60)).collect();
        Arc::new(T2Chain(Mutex::new(ChainState {
            t0,
            jitter,
            now: t0,
            addresses: vec![address(0)],
            txs: Vec::new(),
            next_txid: 1,
            txid_seed,
            log: Vec::new(),
            failure: None,
        })))
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, ChainState> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_now(&self, now: u64) {
        let mut c = self.lock();
        c.now = c.now.max(now);
    }

    /// Pays `amount` to `minor`, first seen at `seen`, mined `delay` blocks after the next one.
    pub fn pay(&self, minor: u32, amount: u64, seen: u64, delay: u64) -> [u8; 32] {
        let mut c = self.lock();
        // A transaction id is a hash: random-looking, from the payer's side of the chain.
        let txid = super::rng::derive32(c.txid_seed, &[b"txid", &c.next_txid.to_be_bytes()]);
        c.next_txid += 1;
        let block = c.first_block_after(seen) + delay;
        c.txs.push(ChainTx {
            txid,
            minor,
            amount,
            first_seen: seen,
            block,
        });
        txid
    }

    /// The time at which a transfer first seen at `seen` with `delay` reaches `confirmations`.
    pub fn confirmed_at(&self, seen: u64, delay: u64, confirmations: u64) -> u64 {
        let c = self.lock();
        let block = c.first_block_after(seen) + delay;
        c.block_time(block + confirmations - 1)
    }

    pub fn minor_of(&self, text: &str) -> Option<u32> {
        self.lock()
            .addresses
            .iter()
            .position(|a| a == text)
            .map(|m| m as u32)
    }

    pub fn drain_log(&self) -> Vec<WalletLog> {
        std::mem::take(&mut self.lock().log)
    }
}

impl ChainState {
    fn block_time(&self, k: u64) -> u64 {
        self.t0 + BLOCK_SECS * k + self.jitter[(k as usize) % self.jitter.len()]
    }

    /// Blocks produced at or before `t` (after the start).
    fn produced(&self, t: u64) -> u64 {
        if t < self.t0 {
            return 0;
        }
        let mut k = (t - self.t0) / BLOCK_SECS;
        while k > 0 && self.block_time(k) > t {
            k -= 1;
        }
        while self.block_time(k + 1) <= t {
            k += 1;
        }
        k
    }

    fn first_block_after(&self, t: u64) -> u64 {
        self.produced(t) + 1
    }

    fn blocks(&self) -> u64 {
        START_BLOCKS + self.produced(self.now)
    }

    fn entry(&self, t: &ChainTx) -> IncomingEntry {
        let produced = self.produced(self.now);
        let (height, confirmations) = if t.block <= produced {
            let h = START_BLOCKS + t.block - 1;
            (Some(h), self.blocks() - h)
        } else {
            (None, 0)
        };
        IncomingEntry {
            minor: t.minor,
            amount_atomic: t.amount,
            height,
            confirmations,
            unlock_time: 0,
            double_spend_seen: false,
            txid: t.txid,
            timestamp: t.first_seen,
        }
    }

    fn record(&mut self, method: &'static str, args: Vec<u64>, entries: Vec<IncomingEntry>) {
        let t = self.now;
        self.log.push(WalletLog {
            t,
            method,
            args,
            address: None,
            entries,
            error: false,
        });
    }
}

/// The issuer's handle on the world's wallet.
pub struct ChainHandle(pub Arc<T2Chain>);

impl PaymentRail for ChainHandle {
    fn new_address(&self) -> Result<(u32, String), RailError> {
        let mut c = self.0.lock();
        if let Some(e) = c.failure {
            return Err(e);
        }
        let minor = c.addresses.len() as u32;
        let text = address(minor);
        c.addresses.push(text.clone());
        let t = c.now;
        c.log.push(WalletLog {
            t,
            method: "create_address",
            args: vec![u64::from(minor)],
            address: Some(text.clone()),
            entries: Vec::new(),
            error: false,
        });
        Ok((minor, text))
    }

    fn address_count(&self) -> Result<u32, RailError> {
        let mut c = self.0.lock();
        let n = c.addresses.len() as u32;
        c.record("get_address_count", vec![u64::from(n)], Vec::new());
        Ok(n)
    }

    fn height(&self) -> Result<RailHeight, RailError> {
        let mut c = self.0.lock();
        let b = c.blocks();
        c.record("get_height", vec![b], Vec::new());
        Ok(RailHeight {
            wallet: b,
            daemon: b,
            synced: true,
        })
    }

    fn transfers(&self, from: u64, to: u64) -> Result<Vec<IncomingEntry>, RailError> {
        let mut c = self.0.lock();
        let now = c.now;
        let out: Vec<IncomingEntry> = c
            .txs
            .iter()
            .filter(|t| t.first_seen <= now && (t.minor as usize) < c.addresses.len())
            .map(|t| c.entry(t))
            .filter(|e| e.height.is_none_or(|h| from <= h && h <= to))
            .collect();
        c.record("get_transfers", vec![from, to], out.clone());
        Ok(out)
    }

    fn transfer_by_txid(&self, txid: &[u8; 32]) -> Result<Option<IncomingEntry>, RailError> {
        let mut c = self.0.lock();
        let now = c.now;
        let e = c
            .txs
            .iter()
            .find(|t| t.txid == *txid && t.first_seen <= now)
            .map(|t| c.entry(t));
        c.record("get_transfer_by_txid", Vec::new(), e.into_iter().collect());
        Ok(e)
    }
}
