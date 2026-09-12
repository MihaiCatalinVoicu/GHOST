//! `ChainPort` (Phase 8 design §7.6, §13.2): an in-memory view-only Monero wallet exposing exactly
//! the fields of `IncomingEntry` the issuer reads. Test-only; it survives issuer crashes (it is the
//! external wallet). Heights are block counts: a transfer mined at height h has
//! `confirmations = blocks − h`, so mining n blocks after it gives it n confirmations.

use std::sync::{Arc, Mutex};

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use ghost_entitlement::monero::base58_encode;
use ghost_issuer::rail::{IncomingEntry, PaymentRail, RailError, RailHeight};
use sha3::{Digest, Keccak256};

/// Mainnet (and regtest) subaddress prefix.
const SUBADDRESS_PREFIX: u8 = 42;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tx {
    pub txid: [u8; 32],
    pub minor: u32,
    pub amount: u64,
    pub unlock_time: u64,
    pub double_spend_seen: bool,
    /// `None` while in the pool.
    pub height: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Chain {
    pub blocks: u64,
    pub daemon_ahead: u64,
    pub synced: bool,
    /// Every call fails with this error while set.
    pub failure: Option<RailError>,
    /// Subaddress texts, index = minor (minor 0 is the primary address's slot).
    pub addresses: Vec<String>,
    pub txs: Vec<Tx>,
    pub next_txid: u64,
}

pub struct ChainPort(Mutex<Chain>);

/// A deterministic, valid regtest subaddress for `minor`: two Ed25519 points, prefix 42,
/// Keccak-256 checksum, Monero Base58.
pub fn address(minor: u32) -> String {
    let point = |x: u64| {
        EdwardsPoint::mul_base(&Scalar::from(x))
            .compress()
            .to_bytes()
    };
    let mut data = vec![SUBADDRESS_PREFIX];
    data.extend_from_slice(&point(u64::from(minor) + 1));
    data.extend_from_slice(&point(u64::from(minor) + 1_000_003));
    let check = Keccak256::digest(&data);
    data.extend_from_slice(&check[..4]);
    base58_encode(&data)
}

impl ChainPort {
    pub fn new(blocks: u64) -> Arc<Self> {
        Self::from_chain(Chain {
            blocks,
            daemon_ahead: 0,
            synced: true,
            failure: None,
            addresses: vec![address(0)],
            txs: Vec::new(),
            next_txid: 1,
        })
    }

    pub fn from_chain(chain: Chain) -> Arc<Self> {
        Arc::new(Self(Mutex::new(chain)))
    }

    pub fn state(&self) -> Chain {
        self.lock().clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Chain> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn blocks(&self) -> u64 {
        self.lock().blocks
    }

    pub fn minor_of(&self, address: &str) -> u32 {
        self.lock()
            .addresses
            .iter()
            .position(|a| a == address)
            .expect("an address of this wallet") as u32
    }

    pub fn subaddress_count(&self) -> u32 {
        self.lock().addresses.len() as u32
    }

    pub fn pay(&self, minor: u32, amount: u64) -> [u8; 32] {
        self.pay_with(minor, amount, 0, false)
    }

    pub fn pay_with(&self, minor: u32, amount: u64, unlock_time: u64, dss: bool) -> [u8; 32] {
        let mut c = self.lock();
        let mut txid = [0u8; 32];
        txid[..8].copy_from_slice(&c.next_txid.to_be_bytes());
        c.next_txid += 1;
        c.txs.push(Tx {
            txid,
            minor,
            amount,
            unlock_time,
            double_spend_seen: dss,
            height: None,
        });
        txid
    }

    /// Mines every pool transfer (except double-spent ones) at the current height, then adds
    /// `n` blocks.
    pub fn mine(&self, n: u64) {
        let mut c = self.lock();
        let at = c.blocks;
        for t in c.txs.iter_mut() {
            if t.height.is_none() && !t.double_spend_seen {
                t.height = Some(at);
            }
        }
        c.blocks += n;
    }

    /// Adds `n` blocks that mine nothing: pool transfers stay in the pool (a miner that leaves a
    /// transaction out, so it is mined later, at a greater height).
    pub fn mine_empty(&self, n: u64) {
        self.lock().blocks += n;
    }

    /// Removes the top `n` blocks; their transfers go back to the pool (`keep`) or vanish.
    pub fn pop(&self, n: u64, keep: bool) {
        let mut c = self.lock();
        c.blocks -= n;
        let top = c.blocks;
        c.txs.retain_mut(|t| match t.height {
            Some(h) if h >= top => {
                t.height = None;
                keep
            }
            _ => true,
        });
    }

    pub fn set_synced(&self, synced: bool) {
        self.lock().synced = synced;
    }

    pub fn set_daemon_ahead(&self, blocks: u64) {
        self.lock().daemon_ahead = blocks;
    }

    pub fn set_failure(&self, failure: Option<RailError>) {
        self.lock().failure = failure;
    }

    fn entry(c: &Chain, t: &Tx) -> IncomingEntry {
        IncomingEntry {
            minor: t.minor,
            amount_atomic: t.amount,
            height: t.height,
            confirmations: t.height.map_or(0, |h| c.blocks - h),
            unlock_time: t.unlock_time,
            double_spend_seen: t.double_spend_seen,
            txid: t.txid,
            timestamp: 0,
        }
    }
}

impl PaymentRail for ChainPort {
    fn new_address(&self) -> Result<(u32, String), RailError> {
        let mut c = self.lock();
        if let Some(e) = c.failure {
            return Err(e);
        }
        let minor = c.addresses.len() as u32;
        let text = address(minor);
        c.addresses.push(text.clone());
        Ok((minor, text))
    }

    fn address_count(&self) -> Result<u32, RailError> {
        let c = self.lock();
        match c.failure {
            Some(e) => Err(e),
            None => Ok(c.addresses.len() as u32),
        }
    }

    fn height(&self) -> Result<RailHeight, RailError> {
        let c = self.lock();
        match c.failure {
            Some(e) => Err(e),
            None => Ok(RailHeight {
                wallet: c.blocks,
                daemon: c.blocks + c.daemon_ahead,
                synced: c.synced,
            }),
        }
    }

    fn transfers(&self, from: u64, to: u64) -> Result<Vec<IncomingEntry>, RailError> {
        let c = self.lock();
        if let Some(e) = c.failure {
            return Err(e);
        }
        Ok(c.txs
            .iter()
            .filter(|t| t.height.is_none_or(|h| from <= h && h <= to))
            .map(|t| Self::entry(&c, t))
            .collect())
    }

    fn transfer_by_txid(&self, txid: &[u8; 32]) -> Result<Option<IncomingEntry>, RailError> {
        let c = self.lock();
        if let Some(e) = c.failure {
            return Err(e);
        }
        Ok(c.txs
            .iter()
            .find(|t| t.txid == *txid)
            .map(|t| Self::entry(&c, t)))
    }
}

/// A handle the issuer owns while the test keeps the wallet.
pub struct RailHandle(pub Arc<ChainPort>);

impl PaymentRail for RailHandle {
    fn new_address(&self) -> Result<(u32, String), RailError> {
        self.0.new_address()
    }
    fn address_count(&self) -> Result<u32, RailError> {
        self.0.address_count()
    }
    fn height(&self) -> Result<RailHeight, RailError> {
        self.0.height()
    }
    fn transfers(&self, from: u64, to: u64) -> Result<Vec<IncomingEntry>, RailError> {
        self.0.transfers(from, to)
    }
    fn transfer_by_txid(&self, txid: &[u8; 32]) -> Result<Option<IncomingEntry>, RailError> {
        self.0.transfer_by_txid(txid)
    }
}
