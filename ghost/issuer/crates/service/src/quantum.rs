//! The wall-clock facade (Phase 8 design §2.8, §5.1, §5.9, §6.2): what the gRPC service calls.
//! It adds only the wall clock, the blocking pool, the signing semaphore and the fixed reply
//! quantum to the `*_at(request, now)` handlers.
//!
//! - Every handler runs on `spawn_blocking` (redb and signing are synchronous).
//! - `BlindSign` and `RedeemInvite` take a permit of a semaphore sized to the core count first,
//!   so a burst of signing cannot starve the scanner, and their responses (errors included)
//!   leave at `t_request + Q · max(1, ceil(elapsed / Q))` with Q = 2 s (Q18): over Tor the signing
//!   time is visible only at the quantum's granularity, whichever signer is in use.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ghost_issuer_api::proto as wire;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use tonic::Status;

use crate::service::{unavailable, Issuer};

/// The reply quantum Q of `BlindSign` and `RedeemInvite` (§2.8, Q18).
pub const REPLY_QUANTUM: Duration = Duration::from_secs(2);

/// Seconds since the Unix epoch, the `now` of every handler called from the network.
pub fn wall_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The clock of the network handlers and the periodic jobs, in seconds since the Unix epoch;
/// injected (relay precedent), so the whole process runs on a virtual clock in tests.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The wall clock ([`wall_now`]).
pub fn wall_clock() -> Clock {
    Arc::new(wall_now)
}

/// A fixed reply quantum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplyQuantum(Duration);

impl ReplyQuantum {
    /// A quantum of at least one millisecond.
    pub fn new(q: Duration) -> Self {
        Self(q.max(Duration::from_millis(1)))
    }

    pub fn period(&self) -> Duration {
        self.0
    }

    /// How long after the request the response leaves: the first positive multiple of Q at or
    /// after `elapsed`.
    pub fn release_after(&self, elapsed: Duration) -> Duration {
        let q = self.0.as_nanos();
        let n = elapsed.as_nanos().div_ceil(q).max(1);
        let total = n.saturating_mul(q);
        Duration::from_nanos(u64::try_from(total).unwrap_or(u64::MAX))
    }
}

impl Default for ReplyQuantum {
    fn default() -> Self {
        Self::new(REPLY_QUANTUM)
    }
}

/// The issuer as the network sees it.
pub struct TimedIssuer {
    issuer: Arc<Issuer>,
    quantum: ReplyQuantum,
    signing: Arc<Semaphore>,
    clock: Clock,
}

impl TimedIssuer {
    /// `signing_permits`: concurrent signing calls (the core count in production). Handlers see
    /// the wall clock.
    pub fn new(issuer: Arc<Issuer>, quantum: ReplyQuantum, signing_permits: usize) -> Self {
        Self::with_clock(issuer, quantum, signing_permits, wall_clock())
    }

    /// [`TimedIssuer::new`] with handlers on `clock`.
    pub fn with_clock(
        issuer: Arc<Issuer>,
        quantum: ReplyQuantum,
        signing_permits: usize,
        clock: Clock,
    ) -> Self {
        Self {
            issuer,
            quantum,
            signing: Arc::new(Semaphore::new(signing_permits.max(1))),
            clock,
        }
    }

    pub fn issuer(&self) -> &Arc<Issuer> {
        &self.issuer
    }

    async fn blocking<T, F>(&self, f: F) -> Result<T, Status>
    where
        T: Send + 'static,
        F: FnOnce(&Issuer, u64) -> Result<T, Status> + Send + 'static,
    {
        let issuer = Arc::clone(&self.issuer);
        let clock = Arc::clone(&self.clock);
        tokio::task::spawn_blocking(move || f(&issuer, clock()))
            .await
            .map_err(|_| unavailable())?
    }

    async fn quantized<T, F>(&self, f: F) -> Result<T, Status>
    where
        T: Send + 'static,
        F: FnOnce(&Issuer, u64) -> Result<T, Status> + Send + 'static,
    {
        let received = Instant::now();
        let result = match Arc::clone(&self.signing).acquire_owned().await {
            Ok(permit) => {
                let issuer = Arc::clone(&self.issuer);
                let clock = Arc::clone(&self.clock);
                // The permit moves into the blocking work and is released when that work ends. A
                // caller that stops waiting (a client grpc-timeout, a reset stream) drops only this
                // future, so it cannot free the permit while its signing still runs (§5.9).
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    f(&issuer, clock())
                })
                .await
                .unwrap_or_else(|_| Err(unavailable()))
            }
            Err(_) => Err(unavailable()),
        };
        tokio::time::sleep_until(received + self.quantum.release_after(received.elapsed())).await;
        result
    }

    pub async fn request_invoice(
        &self,
        req: wire::RequestInvoiceRequest,
    ) -> Result<wire::RequestInvoiceResponse, Status> {
        self.blocking(move |i, now| i.request_invoice_at(req, now))
            .await
    }

    pub async fn blind_sign(
        &self,
        req: wire::BlindSignRequest,
    ) -> Result<wire::BlindSignResponse, Status> {
        self.quantized(move |i, now| i.blind_sign_at(req, now))
            .await
    }

    pub async fn invoice_status(
        &self,
        req: wire::InvoiceStatusRequest,
    ) -> Result<wire::InvoiceStatusResponse, Status> {
        self.blocking(move |i, now| i.invoice_status_at(req, now))
            .await
    }

    pub async fn redeem_invite(
        &self,
        req: wire::RedeemInviteRequest,
    ) -> Result<wire::RedeemInviteResponse, Status> {
        self.quantized(move |i, now| i.redeem_invite_at(req, now))
            .await
    }

    pub async fn claim_payout(
        &self,
        req: wire::ClaimPayoutRequest,
    ) -> Result<wire::ClaimPayoutResponse, Status> {
        self.blocking(move |i, now| i.claim_payout_at(req, now))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_is_the_first_positive_multiple_of_the_quantum() {
        let q = ReplyQuantum::new(Duration::from_secs(2));
        assert_eq!(q.release_after(Duration::ZERO), Duration::from_secs(2));
        assert_eq!(
            q.release_after(Duration::from_millis(1)),
            Duration::from_secs(2)
        );
        assert_eq!(
            q.release_after(Duration::from_secs(2)),
            Duration::from_secs(2)
        );
        assert_eq!(
            q.release_after(Duration::from_millis(2_001)),
            Duration::from_secs(4)
        );
        assert_eq!(
            q.release_after(Duration::from_millis(5_300)),
            Duration::from_secs(6)
        );
        assert_eq!(ReplyQuantum::default().period(), REPLY_QUANTUM);
    }
}
