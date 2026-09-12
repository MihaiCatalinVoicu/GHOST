//! Credit tokens presented to the issuer (Phase 8 design §4.6, §5.6, §19.8): verification under an
//! ES CREDIT key of an accepted epoch, the smallest-covering-set rule of a credits-paid pack and
//! the spent check. A credit's value is the pack price of its own epoch divided by 10, whatever
//! the epoch it is redeemed in (MS-4 across price changes).

use std::collections::BTreeSet;

use ghost_entitlement::grid::{credit_epoch, week};
use ghost_entitlement::{Expect, Schedule, Token};
use ghost_issuer_api::MAX_DISCOUNT_CREDITS;

use crate::store::{self, ReadTx, StoreError};

/// A credit is accepted in its epoch and the four following ones (52–65 weeks, §19.8).
pub const ACCEPTED_PAST_EPOCHS: u64 = 4;

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
}
