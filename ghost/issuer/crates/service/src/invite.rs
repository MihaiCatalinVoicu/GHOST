//! `RedeemInvite` (Phase 8 design §5.6, §8.3, §8.7, §19.9): an unspent invite token buys a trial,
//! blind access tokens for the base week and the next one under the ordinary access keys. The
//! issuer keeps only `invite_nullifier[(epoch, N)] → trial digest` (journaled, until the start of
//! epoch + 2) and the trial counters.
//!
//! Order: sizes; the token verifies under an ES INVITE key of **any** listed epoch; the nullifier
//! lookup (an identical request is re-served whatever the epoch, a different one is `REPLAYED`);
//! only then the acceptance window, revocation and closed epochs, and the base week (§19.9).

use ghost_entitlement::batch::{self, Layout};
use ghost_entitlement::grid::{invite_epoch, week};
use ghost_entitlement::token::TOKEN_LEN;
use ghost_entitlement::{Kind, Schedule, Token};
use ghost_issuer_api::proto as wire;
use ghost_issuer_api::{BLOCK_BYTES, MAX_LAYOUT_POSITIONS};
use tonic::Status;

use crate::journal::Entry;
use crate::service::{base_week_ok, rejected, unauthorized, unavailable, Issuer, SignFailure};
use crate::store::{self, MetaKey};
use crate::PROTOCOL_VERSION;

/// Verifies an issuer-verified token (INVITE or CREDIT) under the ES key its `token_key_id`
/// names, **whatever that epoch's revocation state**: the key must be of `kind`, the challenge
/// digest must be the issuer challenge of its epoch, and `ring` must verify. Returns the epoch.
/// Revocation and the acceptance window are the caller's checks, made only for new redemptions.
pub(crate) fn verify_issuer_token(schedule: &Schedule, token: &Token, kind: Kind) -> Option<u64> {
    let entry = schedule.key_by_id(token.key_id())?;
    if entry.kind != kind {
        return None;
    }
    let digest = schedule.challenge_digest(kind, entry.epoch, None).ok()?;
    if digest.as_slice() != token.challenge_digest() {
        return None;
    }
    token.verify_signature(&entry.public_key).ok()?;
    Some(entry.epoch)
}

fn answer(result: wire::RedeemInviteResult, sigs: Vec<u8>) -> wire::RedeemInviteResponse {
    wire::RedeemInviteResponse {
        result: result as i32,
        blind_signatures: sigs,
    }
}

impl Issuer {
    /// `RedeemInvite` (§5.6).
    pub fn redeem_invite_at(
        &self,
        req: wire::RedeemInviteRequest,
        now: u64,
    ) -> Result<wire::RedeemInviteResponse, Status> {
        self.ensure_running()?;
        // 1. Sizes.
        if req.version != PROTOCOL_VERSION
            || req.invite_token.len() != TOKEN_LEN
            || req.blinded.is_empty()
            || !req.blinded.len().is_multiple_of(BLOCK_BYTES)
            || req.blinded.len() > MAX_LAYOUT_POSITIONS * BLOCK_BYTES
        {
            return Err(rejected());
        }
        // 2. A valid invite token of any listed epoch.
        let token = Token::parse(&req.invite_token).map_err(|_| unauthorized())?;
        let epoch =
            verify_issuer_token(&self.schedule, &token, Kind::Invite).ok_or_else(unauthorized)?;
        // 3. Nullifier and trial digest.
        let nullifier = token.nullifier();
        let digest = batch::trial_digest(&nullifier, req.base_week, &req.blinded);
        // 4. Idempotency before validity.
        if let Some(stored) = store::invite_nullifier(&*self.store.read()?, epoch, &nullifier)? {
            return self.reserve_trial(stored == digest, req.base_week, &req.blinded);
        }
        // 5. New redemptions only: the acceptance window, revocation, closed epochs, base week.
        let e_now = invite_epoch(week(now));
        let closed = self.closed_through(MetaKey::ClosedThroughInviteEpoch)?;
        if !(epoch == e_now || epoch.saturating_add(1) == e_now)
            || self.schedule.is_revoked(Kind::Invite, epoch)
            || closed.is_some_and(|c| epoch <= c)
        {
            return Err(unauthorized());
        }
        if !base_week_ok(req.base_week, now) {
            return Ok(answer(wire::RedeemInviteResult::WrongPeriod, Vec::new()));
        }
        // 6. The trial layout and ranges.
        let layout = Layout::trial(&self.schedule, req.base_week).map_err(|_| unavailable())?;
        self.check_blocks(&layout, &req.blinded)?;
        // 7. Sign, then one decided transaction; a loser of the re-check continues at step 4.
        let sigs = self
            .sign_all(&layout, &req.blinded)
            .map_err(SignFailure::status)?;
        let tx = self.store.write()?;
        if let Some(stored) = store::invite_nullifier(&*tx, epoch, &nullifier)? {
            drop(tx);
            drop(sigs);
            return self.reserve_trial(stored == digest, req.base_week, &req.blinded);
        }
        self.decide(
            tx,
            &Entry::Invite {
                epoch,
                nullifier,
                digest,
                base_week: req.base_week,
            },
            now,
            0,
        )?;
        Ok(answer(wire::RedeemInviteResult::Ok, sigs))
    }

    /// Step 4: an identical request is re-signed while the trial's keys are held (at least until
    /// `end(base + 1) + 8 d`, §19.1 rule 2); afterwards, and for any other request, `REPLAYED`.
    fn reserve_trial(
        &self,
        same: bool,
        base_week: u64,
        blinded: &[u8],
    ) -> Result<wire::RedeemInviteResponse, Status> {
        let replayed = || Ok(answer(wire::RedeemInviteResult::Replayed, Vec::new()));
        if !same {
            return replayed();
        }
        let Ok(layout) = Layout::trial(&self.schedule, base_week) else {
            return replayed();
        };
        let held = {
            let keys = self.keys();
            layout
                .positions()
                .iter()
                .all(|p| keys.contains(p.kind, p.epoch))
        };
        if !held || blinded.len() != layout.len() * BLOCK_BYTES {
            return replayed();
        }
        match self.sign_all(&layout, blinded) {
            Ok(sigs) => Ok(answer(wire::RedeemInviteResult::Ok, sigs)),
            Err(SignFailure::KeysMissing) => replayed(),
            Err(e) => Err(e.status()),
        }
    }
}
