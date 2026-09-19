//! Bearer credentials v3 at the relay (Phase 9 design §4.3, §4.5, §21.2, §22.8.7): the operations
//! each kind allows, the slot and namespace checks, the registrations behind a credential, and the
//! coarse times a `get` with a credential answers with.
//!
//! A credential carries no MAC; its authority is a live `bearer_keys` record of its verifier in
//! `keys.redb`. Every refusal a client can cause (a kind that does not allow the operation, a relay
//! without a slot, another slot, another namespace, an unregistered or lapsed verifier) is one
//! answer, `PERMISSION_DENIED` with capture `rejected_capability`: no oracle.
//!
//! The verifier names the ES slot, not the serving relay, so the slot check bounds replay across
//! slots and not across a slot handover: an operator that held slot s can present the secrets it
//! saw at the slot's successor relay, which registers the same static verifiers. Declared as
//! LIMITE L7-D26 (design §4.3, §21.2 point 11); binding the verifier to the relay's onion identity
//! is the Phase 13 alternative.

use std::ops::RangeInclusive;

use ghost_entitlement::grid;
use ghost_relay_api::{BearerCredential, BearerKind, VERIFIER_BYTES};
use ghost_relay_capability::{bearer_verifier, Allowance};
use ghost_relay_storage::keys::BearerRecord;
use tonic::Status;

use crate::{Relay, REJECTED, UNAUTHORIZED};

/// A relay operation a credential may authorize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    Store,
    Get,
    Check,
    List,
}

/// The kind/operation matrix: read → list, get, check; deposit → store, check; fetch → list, get.
pub(crate) fn allows(kind: BearerKind, op: Op) -> bool {
    matches!(
        (kind, op),
        (BearerKind::Read, Op::List | Op::Get | Op::Check)
            | (BearerKind::Deposit, Op::Store | Op::Check)
            | (BearerKind::Fetch, Op::List | Op::Get)
    )
}

/// Why a credential was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Every refusal a client can cause.
    Unauthorized,
    /// `keys.redb` could not be read.
    Unavailable,
}

impl Refusal {
    pub(crate) fn status(self) -> Status {
        match self {
            Refusal::Unauthorized => Status::permission_denied(UNAUTHORIZED),
            Refusal::Unavailable => Status::unavailable(REJECTED),
        }
    }
}

/// A credential the relay accepted: its verifier and the live registrations behind it, earliest
/// `valid_until` first.
pub(crate) struct Accepted {
    pub verifier: [u8; VERIFIER_BYTES],
    pub records: Vec<BearerRecord>,
}

impl Accepted {
    /// The allowances of the deposit registrations behind a deposit credential, in charging order.
    pub(crate) fn allowances(&self, credential: &BearerCredential) -> Vec<Allowance> {
        self.records
            .iter()
            .map(|r| Allowance {
                record: (credential.namespace, r.period, self.verifier),
                quota_bytes: r.quota_bytes,
                valid_until: r.valid_until,
            })
            .collect()
    }
}

/// The weeks whose registrations may authorize a credential at `now`, by the relay's own clock:
/// `[week(now) - 3, week(now) + 1]` (design §21.2 point 5). Only records live at `now` count.
pub(crate) fn lookup_periods(now: u64) -> RangeInclusive<u64> {
    let w = grid::week(now);
    w.saturating_sub(3)..=w.saturating_add(1)
}

/// The `uploaded_at` a `get` with a credential answers with: the start of the upload's ISO week
/// (design §21.9 point 4).
pub(crate) fn week_floor(t: u64) -> u64 {
    grid::week_start(grid::week(t)).min(t)
}

/// The expiry a `get` with a fetch credential answers with: rounded up to the next ISO week
/// boundary, unchanged on a boundary (design §22.8.7 point 1).
pub(crate) fn week_ceil(t: u64) -> u64 {
    let start = grid::week_start(grid::week(t));
    if start >= t {
        start
    } else {
        grid::week_start(grid::week(t).saturating_add(1))
    }
}

impl Relay {
    /// Accepts `credential` for `op` at `now`, or refuses it. Checks run in this order: the kind
    /// allows `op`; the relay has a slot and it is the credential's (before any verifier is
    /// computed, so a secret seen at another relay is refused here); `namespace`, for operations
    /// that name one, is the credential's; a record of the credential's verifier, of its kind and
    /// namespace, is live for some week of [`lookup_periods`].
    pub(crate) fn accept_bearer(
        &self,
        credential: &BearerCredential,
        op: Op,
        namespace: Option<&[u8; 32]>,
        now: u64,
    ) -> Result<Accepted, Refusal> {
        if !allows(credential.kind, op) || self.slot() != Some(credential.slot) {
            return Err(Refusal::Unauthorized);
        }
        if namespace.is_some_and(|ns| *ns != credential.namespace) {
            return Err(Refusal::Unauthorized);
        }
        let verifier = bearer_verifier(credential);
        let records = self
            .key_store()
            .live_records(
                &credential.namespace,
                credential.kind.byte(),
                &verifier,
                lookup_periods(now),
                now,
            )
            .map_err(|_| Refusal::Unavailable)?;
        if records.is_empty() {
            return Err(Refusal::Unauthorized);
        }
        Ok(Accepted { verifier, records })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rights_matrix_is_exactly_the_design_table() {
        let ops = [Op::Store, Op::Get, Op::Check, Op::List];
        let allowed = |kind| {
            ops.iter()
                .copied()
                .filter(|&op| allows(kind, op))
                .collect::<Vec<_>>()
        };
        assert_eq!(allowed(BearerKind::Read), [Op::Get, Op::Check, Op::List]);
        assert_eq!(allowed(BearerKind::Deposit), [Op::Store, Op::Check]);
        assert_eq!(allowed(BearerKind::Fetch), [Op::Get, Op::List]);
    }

    #[test]
    fn week_rounding_and_lookup_periods() {
        let p = 2959;
        let start = grid::week_start(p);
        let next = grid::week_start(p + 1);
        assert_eq!(week_floor(start), start);
        assert_eq!(week_floor(start + 1), start);
        assert_eq!(week_floor(next - 60), start);
        assert_eq!(week_ceil(start), start);
        assert_eq!(week_ceil(start + 1), next);
        assert_eq!(week_ceil(next - 1), next);
        assert_eq!(week_floor(5), 5);
        assert_eq!(lookup_periods(start), p - 3..=p + 1);
        assert_eq!(lookup_periods(next - 1), p - 3..=p + 1);
        assert_eq!(lookup_periods(0), 0..=1);
    }
}
