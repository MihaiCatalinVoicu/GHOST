//! An in-process relay serving one slot of an Entitlement Schedule (Phase 8 design §10; regtest
//! step 14 and its in-process twin): the real `Relay::redeem_at`, a fresh nullifier store, and the
//! relay's own onion taken from the schedule's slot table.

use std::path::Path;
use std::sync::Arc;

use ghost_entitlement::grid::week;
use ghost_entitlement::onion::Onion;
use ghost_entitlement::{Schedule, Token};
use ghost_relay_api::proto::{RedeemResult, RedeemTokenRequest, RedeemTokenResponse};
use ghost_relay_api::PROTOCOL_VERSION;
use ghost_relay_capability::RelayKey;
use ghost_relay_node::{EntitlementPolicy, NullifierMode, Relay, RelayConfig};
use tonic::Status;

/// A relay of `slot` in `dir`, whose clock stays at `now`.
pub fn relay_for_slot(dir: &Path, schedule: &Schedule, slot: u8, now: u64) -> Arc<Relay> {
    let onion = schedule
        .slot_onion(slot, week(now))
        .expect("the slot serves this week");
    let onion = Onion::parse(onion).unwrap().pubkey;
    let mut policy = EntitlementPolicy::new(schedule.clone(), slot, onion).unwrap();
    policy.nullifiers = NullifierMode::Create;
    Relay::open(
        dir,
        RelayKey::from_bytes([0x42; 32]),
        RelayConfig {
            entitlement: Some(policy),
            clock: Arc::new(move || now),
            ..RelayConfig::default()
        },
        None,
    )
    .unwrap()
}

/// `RedeemToken` of `token` for `namespace`.
pub fn redeem(
    relay: &Relay,
    token: &Token,
    namespace: &[u8; 32],
    request_id: &[u8; 16],
    now: u64,
) -> Result<RedeemTokenResponse, Status> {
    relay.redeem_at(
        RedeemTokenRequest {
            version: PROTOCOL_VERSION,
            token: token.as_bytes().to_vec(),
            namespace_id: namespace.to_vec(),
            request_id: request_id.to_vec(),
        },
        now,
    )
}

/// The capability of an `OK` redemption.
pub fn capability(r: &RedeemTokenResponse) -> Option<Vec<u8>> {
    if r.result == RedeemResult::Ok as i32 {
        r.capability.as_ref().map(|c| c.token.clone())
    } else {
        None
    }
}
