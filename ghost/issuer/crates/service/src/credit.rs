//! Credit tokens presented to the issuer (Phase 8 design §4.6, §5.6, §19.8): verification under an
//! ES CREDIT key of an accepted epoch, the smallest-covering-set rule of a credits-paid pack, the
//! spent check, and `RefreshCredit`. A credit's value is the pack price of its own epoch divided by
//! 10, whatever the epoch it is redeemed in (MS-4 across price changes).
//!
//! **`RefreshCredit`** (§5.6, §19.8 point 3): a credit received through a drop is known to the
//! invitee who finalized it (and, under AD-1, may have been minted by the operator), so the
//! inviter exchanges it for one fresh blind credit of the **same** epoch before any use. Order:
//! sizes; the credit verifies under an ES CREDIT key of any listed epoch (whatever its revocation
//! state); the nullifier lookup (a refresh with the same blinded value is re-signed, any other use
//! of the nullifier is `REPLAYED`: idempotency before validity, §19.9); only then the epoch
//! (`c_now` or `c_now − 1`, not revoked, not closed) and the blinded value's range. One decided
//! transaction records the nullifier with `use = refresh` and the whole refresh digest (§5.6 step
//! 3 re-serves "the same blinded digest": all 32 bytes are compared, so a second request cannot
//! pass for the first by sharing a prefix of its digest), and counts `credits_refreshed` and
//! `signed[CREDIT]` of the epoch (net zero for the cap).
//! A re-serve after the epoch's key was destroyed (`end(c + 1) + 8 d`, §19.1) answers `REPLAYED`,
//! as a trial re-serve does (§19.1 rule 2).
//!
//! **Refresh budget** (§19.27, S12 review CR-RF-1). A refreshed credit is an ordinary credit of
//! the same epoch, so a credit holder could refresh one credit in a chain for free: every link
//! journals and syncs an entry, keeps a nullifier row for 52–65 weeks and signs under the CREDIT
//! key (a non-adaptive signing oracle outside the payment gate of §2.8 point 1). New refreshes of
//! epoch e stop at [`refresh_budget`]: `refresh_floor` plus the XMR packs whose base week lies in
//! credit epoch e − 1, e or e + 1. That is the honest maximum plus the floor: every honest refresh
//! consumes one received drop credit, a drop is written once per invitee and carries a credit only
//! when that invitee paid its first XMR pack before its drop time (§9.3), and that pack's epoch is
//! within one of e (a refresh of e happens while `c_now ∈ {e, e + 1}`, after its drop, which comes
//! at most 8 weeks after the invitee's base week). Beyond it the answer is `RESOURCE_EXHAUSTED`
//! (the client's `quota`, a transient retry), counted in the status key `REFRESH_REFUSED`; the
//! check runs before signing and again inside the decided transaction. Recorded refreshes are
//! re-served whatever the budget. Declared residue (§19.27): a credit holder who spends an epoch's
//! budget denies the honest refreshes of that epoch until more XMR packs raise it.

use std::collections::BTreeSet;

use ghost_entitlement::batch::Layout;
use ghost_entitlement::grid::{credit_epoch, week, WEEKS_PER_CREDIT_EPOCH};
use ghost_entitlement::token::TOKEN_LEN;
use ghost_entitlement::{Expect, Kind, Schedule, Token};
use ghost_issuer_api::proto as wire;
use ghost_issuer_api::{BLOCK_BYTES, MAX_DISCOUNT_CREDITS};
use sha2::{Digest, Sha256};
use tonic::Status;

use crate::invite::verify_issuer_token;
use crate::journal::Entry;
use crate::reconcile::{self, CounterId};
use crate::service::{exhausted, rejected, unauthorized, unavailable, Issuer, SignFailure};
use crate::store::{self, CreditUse, MetaKey, ReadTx, StoreError};
use crate::PROTOCOL_VERSION;

/// A credit is accepted in its epoch and the four following ones (52–65 weeks, §19.8).
pub const ACCEPTED_PAST_EPOCHS: u64 = 4;

const REFRESH_DOMAIN: &[u8] = b"ghost/v1/refresh-credit";

/// One verified credit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PresentedCredit {
    pub epoch: u64,
    pub nullifier: [u8; 32],
    /// `price(epoch) / 10`.
    pub value: u64,
}

/// Every token verifies as a CREDIT token (`ring`, origin `"issuer-credit"`, not revoked) of an
/// epoch in `c_now − 4 … c_now` that is not closed (§19.10), and the nullifiers are distinct.
/// `None` refuses the set (`PERMISSION_DENIED`).
pub fn verify(
    schedule: &Schedule,
    tokens: &[Token],
    now: u64,
    closed_through: Option<u64>,
) -> Option<Vec<PresentedCredit>> {
    let c_now = credit_epoch(week(now));
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(tokens.len());
    for token in tokens {
        let v = schedule.verify_token(token, Expect::Credit).ok()?;
        if v.epoch > c_now
            || v.epoch.saturating_add(ACCEPTED_PAST_EPOCHS) < c_now
            || closed_through.is_some_and(|c| v.epoch <= c)
            || !seen.insert(v.nullifier)
        {
            return None;
        }
        out.push(PresentedCredit {
            epoch: v.epoch,
            nullifier: v.nullifier,
            value: schedule.credit_value(v.epoch)?,
        });
    }
    Some(out)
}

/// The set pays for a pack of `price` (§4.6, §19.8): at least `floor` (`credits_per_free_pack`)
/// and at most 20 credits whose values sum to at least the price, and the smallest such set
/// (`ghost_entitlement::credit::covers`, the rule the client checks before it sends a set).
pub fn covers(credits: &[PresentedCredit], price: u64, floor: u8) -> bool {
    let values: Vec<u64> = credits.iter().map(|c| c.value).collect();
    ghost_entitlement::credit::covers(&values, price, floor, MAX_DISCOUNT_CREDITS)
}

/// Bit i is set iff `credits[i]` is already in `credit_nullifier` (any use).
pub fn spent_mask(tx: &dyn ReadTx, credits: &[PresentedCredit]) -> Result<u64, StoreError> {
    let mut mask = 0u64;
    for (i, c) in credits.iter().enumerate().take(64) {
        if store::credit_nullifier(tx, c.epoch, &c.nullifier)?.is_some() {
            mask |= 1 << i;
        }
    }
    Ok(mask)
}

/// The refresh budget of credit epoch `epoch` (§19.27): `floor` plus the XMR packs whose base
/// week lies in credit epoch `epoch − 1`, `epoch` or `epoch + 1` (their counters are kept 58 weeks,
/// longer than any epoch stays refreshable).
pub fn refresh_budget(tx: &dyn ReadTx, epoch: u64, floor: u64) -> Result<u64, StoreError> {
    let first = epoch
        .saturating_sub(1)
        .saturating_mul(WEEKS_PER_CREDIT_EPOCH);
    let end = epoch
        .saturating_add(2)
        .saturating_mul(WEEKS_PER_CREDIT_EPOCH);
    let mut budget = floor;
    for b in first..end {
        budget = budget.saturating_add(reconcile::get(tx, CounterId::PacksXmr, b)?);
    }
    Ok(budget)
}

/// True while epoch `epoch` has refresh budget left: fewer refreshes recorded than
/// [`refresh_budget`].
fn refresh_budget_left(tx: &dyn ReadTx, epoch: u64, floor: u64) -> Result<bool, StoreError> {
    Ok(reconcile::get(tx, CounterId::CreditsRefreshed, epoch)? < refresh_budget(tx, epoch, floor)?)
}

/// `SHA-256("ghost/v1/refresh-credit" || N || blinded)`: the idempotency digest of a refresh, kept
/// whole in the nullifier row.
pub fn refresh_digest(nullifier: &[u8; 32], blinded: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(REFRESH_DOMAIN);
    h.update(nullifier);
    h.update(blinded);
    h.finalize().into()
}

fn refreshed(result: wire::RefreshCreditResult, sig: Vec<u8>) -> wire::RefreshCreditResponse {
    wire::RefreshCreditResponse {
        result: result as i32,
        blind_signature: sig,
    }
}

impl Issuer {
    /// `RefreshCredit` (§5.6, §19.8).
    pub fn refresh_credit_at(
        &self,
        req: wire::RefreshCreditRequest,
        now: u64,
    ) -> Result<wire::RefreshCreditResponse, Status> {
        self.ensure_running()?;
        // 1. Sizes.
        if req.version != PROTOCOL_VERSION
            || req.credit.len() != TOKEN_LEN
            || req.blinded.len() != BLOCK_BYTES
        {
            return Err(rejected());
        }
        // 2. A valid credit of any listed epoch.
        let token = Token::parse(&req.credit).map_err(|_| unauthorized())?;
        let epoch =
            verify_issuer_token(&self.schedule, &token, Kind::Credit).ok_or_else(unauthorized)?;
        let nullifier = token.nullifier();
        let digest = refresh_digest(&nullifier, &req.blinded);
        // 3. Idempotency before validity.
        if let Some(used) = store::credit_nullifier(&*self.store.read()?, epoch, &nullifier)? {
            return self.reserve_refresh(used, &digest, epoch, &req.blinded);
        }
        // 4. New refreshes only: c_now or c_now − 1, not revoked, not closed; the blinded value.
        let c_now = credit_epoch(week(now));
        let closed = self.closed_through(MetaKey::ClosedThroughCreditEpoch)?;
        if !(epoch == c_now || epoch.saturating_add(1) == c_now)
            || self.schedule.is_revoked(Kind::Credit, epoch)
            || closed.is_some_and(|c| epoch <= c)
        {
            return Err(unauthorized());
        }
        let layout = Layout::refresh(&self.schedule, epoch).map_err(|_| unavailable())?;
        self.check_blocks(&layout, &req.blinded)?;
        // The epoch's refresh budget (§19.27): checked before signing and again below.
        let floor = self.params.refresh_floor;
        if !refresh_budget_left(&*self.store.read()?, epoch, floor)? {
            return Err(self.refresh_refused());
        }
        // 5. Sign, then one decided transaction; a loser of the re-check continues at step 3.
        let sig = self
            .sign_all(&layout, &req.blinded)
            .map_err(SignFailure::status)?;
        let tx = self.store.write()?;
        if let Some(used) = store::credit_nullifier(&*tx, epoch, &nullifier)? {
            drop(tx);
            drop(sig);
            return self.reserve_refresh(used, &digest, epoch, &req.blinded);
        }
        // A sweep that closed the epoch since step 4 refuses the new refresh (§19.10).
        if store::meta(&*tx, MetaKey::ClosedThroughCreditEpoch)?.is_some_and(|c| epoch <= c) {
            return Err(unauthorized());
        }
        // A concurrent refresh that took the epoch's last budget since the check above.
        if !refresh_budget_left(&*tx, epoch, floor)? {
            drop(tx);
            drop(sig);
            return Err(self.refresh_refused());
        }
        self.decide(
            tx,
            &Entry::Refresh {
                epoch,
                nullifier,
                digest,
            },
            now,
            0,
        )?;
        Ok(refreshed(wire::RefreshCreditResult::Ok, sig))
    }

    /// A new refresh refused for its epoch's budget: counted (`REFRESH_REFUSED`), then
    /// `RESOURCE_EXHAUSTED`.
    fn refresh_refused(&self) -> Status {
        self.volatile().refresh_refused += 1;
        exhausted()
    }

    /// Step 3: a refresh with the same digest is re-signed while the epoch's key is held; any
    /// other use of the nullifier, and a refresh whose key is gone, is `REPLAYED`.
    fn reserve_refresh(
        &self,
        used: CreditUse,
        digest: &[u8; 32],
        epoch: u64,
        blinded: &[u8],
    ) -> Result<wire::RefreshCreditResponse, Status> {
        let replayed = || Ok(refreshed(wire::RefreshCreditResult::Replayed, Vec::new()));
        if used != CreditUse::Refresh(*digest) {
            return replayed();
        }
        let Ok(layout) = Layout::refresh(&self.schedule, epoch) else {
            return replayed();
        };
        match self.sign_all(&layout, blinded) {
            Ok(sig) => Ok(refreshed(wire::RefreshCreditResult::Ok, sig)),
            Err(SignFailure::KeysMissing) => replayed(),
            Err(e) => Err(e.status()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credits(values: &[u64]) -> Vec<PresentedCredit> {
        values
            .iter()
            .enumerate()
            .map(|(i, &value)| PresentedCredit {
                epoch: 227,
                nullifier: [i as u8; 32],
                value,
            })
            .collect()
    }

    #[test]
    fn ten_credits_of_an_unchanged_price_cover_exactly() {
        assert!(covers(&credits(&[20; 10]), 200, 10));
        assert!(!covers(&credits(&[20; 9]), 200, 10));
        // Eleven credits at an unchanged price are not the smallest set.
        assert!(!covers(&credits(&[20; 11]), 200, 10));
    }

    #[test]
    fn a_price_increase_needs_the_smallest_covering_set() {
        // Credits minted at price 200 (value 20), pack priced 250: 13 credits, not 12 or 14.
        assert!(!covers(&credits(&[20; 12]), 250, 10));
        assert!(covers(&credits(&[20; 13]), 250, 10));
        assert!(!covers(&credits(&[20; 14]), 250, 10));
        // Never more than 20 credits.
        assert!(!covers(&credits(&[1; 21]), 21, 10));
    }

    #[test]
    fn cheaper_credits_after_a_price_drop_still_need_the_floor() {
        // Credits of value 25 (price 250) for a pack of 200: 8 would cover, the floor is 10.
        assert!(!covers(&credits(&[25; 8]), 200, 10));
        assert!(covers(&credits(&[25; 10]), 200, 10));
        assert!(!covers(&credits(&[25; 11]), 200, 10));
    }

    #[test]
    fn the_refresh_digest_binds_the_nullifier_and_the_blinded_value() {
        let d = refresh_digest(&[1; 32], &[2; 256]);
        assert_ne!(d, refresh_digest(&[1; 32], &[3; 256]));
        assert_ne!(d, refresh_digest(&[4; 32], &[2; 256]));
    }
}
