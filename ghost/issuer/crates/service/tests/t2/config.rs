//! What one T2 world is: its scale, its seven seeds, the mutant it runs (if any) and the twin-world
//! perturbations it applies (Phase 8 design §13.4 "Non-interference", §19.16).

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use super::population::Scale;
use super::rng::Seeds;

/// The privacy mutants of §13.5 (M4 is also caught by the `client-core` unit test; M14 is a
/// schedule-level mutant checked on the public context, see `t2_unlinkability.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mutant {
    None,
    M1NonceFromInvoice,
    /// M1 with a GHOST label and the position as HKDF info (J3's label-counter family).
    M1bNonceFromInvoiceLabel,
    M2PerInvoiceKey,
    M2bServerKeyId,
    M3ImmediateEligible,
    M4SharedIssuerScope,
    M5aNoBlinding,
    M5bSquareBlinding,
    M6CrossRelayRetry,
    M7IssuerBaseWeek,
    M8VariableCounts,
    M9SessionIssuerCalls,
    M10ReferralIdAtIssuer,
    M11DeviceClockPeriod,
    M12ClaimInPurchaseRun,
    M13PaidOnboarding,
    M15SeedReuseAcrossFlows,
    M16IssuerForcesRetries,
    M17RelayClockDrivesBaseWeek,
    M18DropAtEligibleMinute,
    M19PayInsideSession,
    M20QuietWhenWorkDue,
    M21SpendReceivedCredit,
}

/// User actions a twin world replays from its base world, so that the declared cells they
/// belong to (L7, the time a user starts a purchase after `ENTITLEMENT_NEEDED`) stay identical
/// while relay activity differs (NI-2, NI-3).
#[derive(Debug, Clone, Default)]
pub struct UserScript {
    /// (client, the foreground session the user started it in, device time before which its
    /// `RequestInvoice` waits).
    pub need_starts: Vec<(u32, u64, i64)>,
    /// The `RefreshCredit` due time of the k-th received credit of a client: (client, k, device
    /// time). A received credit's refresh is due 1–14 days after the inviter's client read the
    /// drop, a time its relay activity sets; the twins that vary relay activity (NI-2, NI-3) keep
    /// this declared cell (E17) fixed, as they keep the purchase starts of L7.
    ///
    /// Keyed by the drop (inviter, invitee), never by arrival order: (inviter, invitee, true time
    /// the inviter's client read the credit, refresh due device time). A twin delivers each credit
    /// at its base world's read time, from the invitee's own record, whatever its relays do: the
    /// read time is relay activity, which NI-2 and NI-3 vary, and the refresh it sets is E17.
    pub receipts: Vec<(u32, u32, u64, i64)>,
    /// The attempt-plan seed of each purchase: (client, instance, seed). The plan is scheduling
    /// randomness (§19.11), which NI-2 keeps while the blinding seeds vary.
    pub plan_seeds: Vec<(u32, u64, [u8; 32])>,
}

#[derive(Clone)]
pub struct Config {
    pub name: String,
    pub scale: Scale,
    pub seeds: Seeds,
    pub mutant: Mutant,
    /// Stream the views into the analyzer.
    pub analyze: bool,
    /// Keep per-client relay call hashes (NI-1 per-client comparison).
    pub per_client: bool,
    /// The complete views as NDJSON, plus `public.json` and `ground_truth.json` (`GHOST_T2_EXPORT`).
    pub export: Option<PathBuf>,
    /// `public.json` and `ground_truth.json` only (`GHOST_T2_TRUTH`).
    pub export_truth: Option<PathBuf>,
    /// A lying issuer layer answers the first `liar` `BlindSign` calls of every invoice
    /// `AWAITING_CONFIRMATIONS` (0: honest).
    pub liar: u32,
    /// Issuer address pool target (NI-1 varies it, so pool minors differ).
    pub pool_target: u32,
    /// NI-1: response latencies up to 30 s (kept inside the minute the client records).
    pub latency_jitter: bool,
    /// NI-1: up to 30 s more on every signing `BlindSign` answer, across minute boundaries, so the
    /// finalization time of a pack moves inside its activation-slot cell.
    pub sign_jitter: bool,
    /// NI-1: payments mined up to two blocks later (kept on the same side of the payer's next
    /// `BlindSign` attempt).
    pub chain_jitter: bool,
    /// NI-1: an extra `UNAVAILABLE` on these `BlindSign` attempts (client, flow instance, attempt).
    pub fail_sign: Arc<HashSet<(u32, u64, usize)>>,
    /// NI-1 across cells: an extra `UNAVAILABLE` on the first `RequestInvoice` of these flows.
    pub fail_request: Arc<HashSet<(u32, u64)>>,
    /// Issuer restores from a snapshot plus the journal: (snapshot day, restore day) of the window.
    pub restores: Vec<(u64, u64)>,
    /// Replay these user actions instead of drawing need-triggered purchases.
    pub script: Option<Arc<UserScript>>,
    /// NI-3: the fraction of clients the relays tell a shifted time.
    pub shift_fraction: f64,
    /// NI-1d: shift the first-purchase start of this fraction of invitees by this many seconds.
    pub first_pack_shift: Option<(f64, u64)>,
}

impl Config {
    pub fn new(name: &str, scale: Scale, seed: u64) -> Self {
        Config {
            name: name.to_string(),
            scale,
            seeds: Seeds::of(seed),
            mutant: Mutant::None,
            analyze: false,
            per_client: false,
            export: None,
            export_truth: None,
            liar: 0,
            pool_target: 32,
            latency_jitter: false,
            sign_jitter: false,
            chain_jitter: false,
            fail_sign: Arc::new(HashSet::new()),
            fail_request: Arc::new(HashSet::new()),
            restores: vec![(scale.window_days / 3, scale.window_days / 3 + 2)],
            script: None,
            shift_fraction: 0.0,
            first_pack_shift: None,
        }
    }
}
