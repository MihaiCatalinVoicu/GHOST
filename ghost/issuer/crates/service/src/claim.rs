//! `ClaimPayout` (Phase 8 design §5.6, §9.4, §19.9): credits are exchanged for a queued XMR payout
//! to a payout address the client typed. The claim is idempotent by `claim_id`, looked up before
//! any address or credit check; the credits are spent in the same decided transaction that queues
//! the claim. Batching, export, the workstation check and acknowledgement are in `payout.rs`.
//!
//! **One pending claim per address** (recorded addition to §5.6 step 5). The workstation pays an
//! address once (§9.5 step 2), so the decided transaction, after its re-checks of the claim id and
//! the credits, answers `ADDRESS_REJECTED` (nothing consumed, nothing journaled) when the address
//! is that of a queued or batched claim: no batch ever holds one address twice. An address of a
//! closed batch is deleted with it and cannot be checked here; the workstation refuses that entry
//! alone. Residue: a holder of unspent credits enough for a claim learns whether an address it
//! already knows belongs to a pending claim.

use ghost_entitlement::monero::{AddressPurpose, MoneroAddress};
use ghost_entitlement::token::TOKEN_LEN;
use ghost_entitlement::Token;
use ghost_issuer_api::proto as wire;
use ghost_issuer_api::CLAIM_ID_BYTES;
use tonic::Status;

use crate::credit;
use crate::journal::{ClaimEntry, Entry, MAX_ENTRY_CREDITS};
use crate::service::{claim_digest, fixed, rejected, unauthorized, Issuer};
use crate::store::{self, ClaimRow, ClaimState, MetaKey, ReadTx, StoreError, ADDRESS_LEN};
use crate::PROTOCOL_VERSION;

/// Longest payout address text accepted before validation (integrated addresses are 106).
const MAX_ADDRESS_TEXT: usize = 128;

fn answer(result: wire::ClaimPayoutResult) -> wire::ClaimPayoutResponse {
    wire::ClaimPayoutResponse {
        result: result as i32,
        ..Default::default()
    }
}

fn known(row: &ClaimRow, digest: &[u8; 32]) -> wire::ClaimPayoutResponse {
    if row.digest == *digest {
        wire::ClaimPayoutResponse {
            result: wire::ClaimPayoutResult::Queued as i32,
            queued_atomic: row.amount,
            spent_mask: 0,
        }
    } else {
        answer(wire::ClaimPayoutResult::ClaimConflict)
    }
}

/// The payout address of a queued or batched claim (closed claims keep none).
fn address_pending(tx: &dyn ReadTx, address: &[u8; ADDRESS_LEN]) -> Result<bool, StoreError> {
    Ok(store::claims(tx)?.iter().any(|(_, c)| {
        matches!(c.state, ClaimState::Queued | ClaimState::Batched) && c.address == *address
    }))
}

fn spent(mask: u64) -> wire::ClaimPayoutResponse {
    wire::ClaimPayoutResponse {
        result: wire::ClaimPayoutResult::CreditsSpent as i32,
        queued_atomic: 0,
        spent_mask: mask,
    }
}

impl Issuer {
    /// `ClaimPayout` (§5.6).
    pub fn claim_payout_at(
        &self,
        req: wire::ClaimPayoutRequest,
        now: u64,
    ) -> Result<wire::ClaimPayoutResponse, Status> {
        self.ensure_running()?;
        // 1. Sizes.
        if req.version != PROTOCOL_VERSION
            || req.claim_id.len() != CLAIM_ID_BYTES
            || req.credits.len() > MAX_ENTRY_CREDITS
            || req.credits.iter().any(|c| c.len() != TOKEN_LEN)
            || req.payout_address.len() > MAX_ADDRESS_TEXT
        {
            return Err(rejected());
        }
        let claim_id: [u8; 16] = fixed(&req.claim_id)?;
        let digest = claim_digest(&req.payout_address, &req.credits);
        // 2. Idempotency before every validity check.
        if let Some(row) = store::claim(&*self.store.read()?, &claim_id)? {
            return Ok(known(&row, &digest));
        }
        // 3. The payout address: ES network, standard or subaddress, checksum, both points.
        let Ok(address) = MoneroAddress::parse(
            &req.payout_address,
            self.schedule.network(),
            AddressPurpose::Payout,
        ) else {
            return Ok(answer(wire::ClaimPayoutResult::AddressRejected));
        };
        let address: [u8; ADDRESS_LEN] = address
            .as_str()
            .as_bytes()
            .try_into()
            .map_err(|_| rejected())?;
        // 4. Credits: count, validity, epochs, then the spent check.
        let c = self.schedule.constants();
        let max = usize::from(c.max_claim_credits).min(MAX_ENTRY_CREDITS);
        if req.credits.len() < usize::from(c.min_claim_credits) || req.credits.len() > max {
            return Err(unauthorized());
        }
        let tokens = req
            .credits
            .iter()
            .map(|t| Token::parse(t))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| unauthorized())?;
        let closed = self.closed_through(MetaKey::ClosedThroughCreditEpoch)?;
        let credits =
            credit::verify(&self.schedule, &tokens, now, closed).ok_or_else(unauthorized)?;
        let mask = credit::spent_mask(&*self.store.read()?, &credits)?;
        if mask != 0 {
            return Ok(spent(mask));
        }
        let amount = credits
            .iter()
            .map(|c| c.value)
            .fold(0u64, u64::saturating_add);
        // 5. One decided transaction; a loser of the re-check journals nothing. A sweep that
        // closed a credit's epoch since step 4 refuses it (its nullifiers may be gone, §19.10).
        let tx = self.store.write()?;
        if let Some(row) = store::claim(&*tx, &claim_id)? {
            return Ok(known(&row, &digest));
        }
        if Self::credits_closed(&*tx, &credits)? {
            return Err(unauthorized());
        }
        let mask = credit::spent_mask(&*tx, &credits)?;
        if mask != 0 {
            return Ok(spent(mask));
        }
        if address_pending(&*tx, &address)? {
            return Ok(answer(wire::ClaimPayoutResult::AddressRejected));
        }
        let entry = Entry::Claim(ClaimEntry {
            claim_id,
            digest,
            amount,
            address,
            credits: credits.iter().map(|c| (c.epoch, c.nullifier)).collect(),
        });
        self.decide(tx, &entry, now, 0)?;
        Ok(wire::ClaimPayoutResponse {
            result: wire::ClaimPayoutResult::Queued as i32,
            queued_atomic: amount,
            spent_mask: 0,
        })
    }
}
