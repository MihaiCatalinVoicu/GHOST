//! The payment rail boundary (Phase 8 design §7.6; FCMP++ contingency, RM §10). The issuer core
//! (scanner, pool, handlers) sees the view-only wallet only through [`PaymentRail`]. The production
//! implementation over `monero-wallet-rpc` (JSON-RPC with digest auth) is slice S5; tests use the
//! `ChainPort` double in `tests/`, which exposes exactly these fields (RP §6.8).
//!
//! Client calls never reach the rail: `BlindSign`, `InvoiceStatus`, `RedeemInvite` and
//! `ClaimPayout` read the database only (§7.3), and `RequestInvoice` takes a pre-created pool entry.

/// Heights of one rail view: the wallet's scanned height and the daemon's height, as block counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RailHeight {
    pub wallet: u64,
    pub daemon: u64,
    /// The daemon reports itself synchronized with the network.
    pub synced: bool,
}

impl RailHeight {
    /// A **synced view** (§5.4): the daemon is synchronized and the wallet is at most one block
    /// behind it. Negative decisions (EXPIRED) and new XMR invoices need one.
    pub fn synced_view(&self) -> bool {
        self.synced && self.wallet.saturating_add(1) >= self.daemon
    }
}

/// One incoming transfer of account 0 (`get_transfers` fields the issuer reads).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IncomingEntry {
    /// Subaddress minor index (major 0).
    pub minor: u32,
    pub amount_atomic: u64,
    /// Block height; `None` for a pool (mempool) transfer.
    pub height: Option<u64>,
    pub confirmations: u64,
    pub unlock_time: u64,
    pub double_spend_seen: bool,
    pub txid: [u8; 32],
    /// `get_transfers` `timestamp`: never read by the issuer logic; exported to the T2 wallet view
    /// only, where the operator has it anyway (§19.11).
    pub timestamp: u64,
}

/// Typed rail failures; there is no catch-all (§7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RailError {
    /// The wallet or daemon is unreachable.
    Transport,
    /// Digest authentication failed.
    Auth,
    /// The wallet answered with an RPC error code.
    Rpc { code: i64 },
    /// The answer does not decode.
    Decode,
    /// The wallet reported a reorganisation deeper than its window (`reorg_depth_error`).
    ReorgDepth,
}

impl std::fmt::Display for RailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RailError::Transport => f.write_str("wallet unreachable"),
            RailError::Auth => f.write_str("wallet authentication failed"),
            RailError::Rpc { code } => write!(f, "wallet rpc error {code}"),
            RailError::Decode => f.write_str("wallet answer does not decode"),
            RailError::ReorgDepth => f.write_str("reorganisation deeper than the wallet window"),
        }
    }
}

impl std::error::Error for RailError {}

/// The view-only wallet as the issuer uses it.
pub trait PaymentRail: Send + Sync {
    /// `create_address {"account_index":0,"count":1}`: the new minor and its address text,
    /// validated by the caller (§7.7).
    fn new_address(&self) -> Result<(u32, String), RailError>;
    /// `get_address {"account_index":0}`: the number of subaddresses of account 0 (startup and
    /// in-process reconciliation of `highest_minor`, §7.2, §19.6).
    fn address_count(&self) -> Result<u32, RailError>;
    /// `refresh` then the wallet and daemon heights.
    fn height(&self) -> Result<RailHeight, RailError>;
    /// `get_transfers {"in":true,"pool":true,"account_index":0,"filter_by_height":true,
    /// "min_height":from,"max_height":to}`: `in` transfers mined in `[from, to]` and every pool
    /// transfer.
    fn transfers(&self, from: u64, to: u64) -> Result<Vec<IncomingEntry>, RailError>;
    /// `get_transfer_by_txid` (restore and reconciliation checks, S5).
    fn transfer_by_txid(&self, txid: &[u8; 32]) -> Result<Option<IncomingEntry>, RailError>;
}
