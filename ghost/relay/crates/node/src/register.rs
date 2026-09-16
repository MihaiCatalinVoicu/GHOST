//! Key registration (Phase 9 design §4.4, §21.2, ADR-30): `RegisterKey` records, with a usable
//! write capability for a namespace, the verifier of a bearer secret for one ISO week, so that the
//! credentials v3 of that secret may read, deposit into or fetch from the namespace at this relay
//! until `start(week + 2) + 1 h`.
//!
//! - The week is judged by the capability, never by the relay's clock: it must be the capability's
//!   week or the next (G-3).
//! - Registrations accumulate and are never replaced (SC-1): a card holder that redeems its own
//!   token for a contact's inbox can add its own verifier, paid by its own capability, but can
//!   neither remove nor replace the owner's. One capability registers at most one verifier per
//!   (namespace, week, kind).
//! - Forged, unknown, expired, foreign and conflicting registrations get one answer
//!   (`PERMISSION_DENIED`, capture `rejected_capability`): no oracle.
//!
//! [`Relay::register_key_at`] applies the checks in exactly the order of design §4.4 and records
//! exactly one capture event.

use ghost_entitlement::grid;
use ghost_relay_api::proto::{RegisterKeyRequest, RegisterKeyResponse, RegisterResult};
use ghost_relay_api::{
    capability_format, time_bucket, BearerKind, CapabilityFormat, HASH_BYTES, PROTOCOL_VERSION,
    REQUEST_ID_BYTES, VERIFIER_BYTES,
};
use ghost_relay_capability::{scope_hash, Kind};
use ghost_relay_storage::keys::{Registered, Registration, SERIAL_BYTES};
use tonic::Status;

use crate::capture::{hex_or_none, Event};
use crate::{fixed, Relay, REJECTED, UNAUTHORIZED};

/// File name of the key registration store inside the data directory (design §4.6).
pub const KEYS_FILE: &str = "keys.redb";

/// The ISO week a verified write capability belongs to (design §4.4 point 3): for a redeemed v2
/// capability, whose expiry is `start(week + 1) + 3600`, `week(expiry - 3601)`; for an
/// operator-minted v1 capability, the week of `now`.
pub fn capability_week(token: &[u8], expiry_unix: u64, now: u64) -> u64 {
    match capability_format(token) {
        Some(CapabilityFormat::V2) => {
            grid::week(expiry_unix.saturating_sub(grid::LATE_WINDOW_SECS.saturating_add(1)))
        }
        _ => grid::week(now),
    }
}

/// The serial a capability registers under: a v2 capability's own 16-byte serial, or the first 16
/// bytes of a v1 capability's scope hash.
pub fn capability_serial(token: &[u8]) -> [u8; SERIAL_BYTES] {
    let mut out = [0u8; SERIAL_BYTES];
    match capability_format(token) {
        Some(CapabilityFormat::V2) => out.copy_from_slice(&token[50..66]),
        _ => out.copy_from_slice(&scope_hash(token)[..SERIAL_BYTES]),
    }
    out
}

/// When a registration of `period` lapses: `start(period + 2) + 3600`.
pub fn registration_valid_until(period: u64) -> u64 {
    grid::week_start(period.saturating_add(2)).saturating_add(grid::LATE_WINDOW_SECS)
}

impl Relay {
    /// RegisterKey at time `now` (unix seconds): design §4.4, exactly one capture event (`op =
    /// "register"`; `key_kind` once the request names a bearer kind; `capability_scope` whenever a
    /// capability is presented; never the verifier).
    pub fn register_key_at(
        &self,
        req: RegisterKeyRequest,
        now: u64,
    ) -> Result<RegisterKeyResponse, Status> {
        let kind = BearerKind::from_key_kind(req.kind);
        let mut event = Event {
            op: "register",
            protocol_version: PROTOCOL_VERSION,
            namespace_id: hex_or_none(&req.namespace_id, HASH_BYTES),
            period_id: Some(hex::encode(grid::epoch_id(req.period_id))),
            key_kind: kind.map(BearerKind::name),
            capability_scope: req
                .capability
                .as_ref()
                .map(|c| hex::encode(scope_hash(&c.token))),
            request_id: hex_or_none(&req.request_id, REQUEST_ID_BYTES),
            time_bucket: time_bucket(now),
            result: "ok",
            ..Default::default()
        };
        let outcome = self.register_steps(&req, kind, now, &mut event);
        self.record(event);
        outcome
    }

    fn register_steps(
        &self,
        req: &RegisterKeyRequest,
        kind: Option<BearerKind>,
        now: u64,
        event: &mut Event,
    ) -> Result<RegisterKeyResponse, Status> {
        // Every answer carries the relay's week and minute (R9 clock sources).
        let answer = |result: RegisterResult, valid_until_unix: u64| RegisterKeyResponse {
            result: result as i32,
            relay_period_id: grid::week(now),
            relay_minute: now / 60,
            valid_until_unix,
        };
        let denied = || Status::permission_denied(UNAUTHORIZED);

        // 1. Version, lengths and kind.
        let (Some(namespace), Some(verifier), Some(kind)) = (
            fixed::<32>(&req.namespace_id),
            fixed::<VERIFIER_BYTES>(&req.verifier),
            kind,
        ) else {
            event.result = "rejected_size";
            return Err(Status::invalid_argument(REJECTED));
        };
        if req.version != PROTOCOL_VERSION || req.request_id.len() != REQUEST_ID_BYTES {
            event.result = "rejected_size";
            return Err(Status::invalid_argument(REJECTED));
        }
        // 2. A usable write capability (v1 or v2) of this relay for the namespace.
        let token = req
            .capability
            .as_ref()
            .map(|c| c.token.as_slice())
            .unwrap_or(&[]);
        let Ok(cap) = self.key.verify(token, Kind::Write, &namespace, now) else {
            event.result = "rejected_capability";
            return Err(denied());
        };
        // 3. The period is the capability's week or the next, whatever the relay's clock says.
        let cap_week = capability_week(token, cap.expiry_unix, now);
        if req.period_id != cap_week && Some(req.period_id) != cap_week.checked_add(1) {
            event.result = "rejected_period";
            return Ok(answer(RegisterResult::WrongPeriod, 0));
        }
        // 4. Accumulate in one write transaction, committed before the answer.
        let valid_until = registration_valid_until(req.period_id);
        let registered = self.keys.register(&Registration {
            namespace,
            period: req.period_id,
            kind: kind.byte(),
            verifier,
            serial: capability_serial(token),
            quota_bytes: cap.quota_bytes,
            valid_until,
        });
        match registered {
            Ok(Registered::Inserted | Registered::Credited | Registered::Unchanged) => {
                Ok(answer(RegisterResult::Ok, valid_until))
            }
            Ok(Registered::Conflict) => {
                event.result = "rejected_capability";
                Err(denied())
            }
            Err(_) => {
                event.result = "rejected_capability";
                Err(Status::unavailable(REJECTED))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_relay_capability::{Capability, RelayKey};

    #[test]
    fn capability_weeks_serials_and_validity() {
        let key = RelayKey::from_bytes([3; 32]);
        let p = 2959;
        let cap = Capability {
            kind: Kind::Write,
            namespace: [1; 32],
            quota_bytes: 10,
            expiry_unix: grid::week_start(p + 1) + 3_600,
        };
        let v2 = key.mint_v2(&cap, &[0xAB; 16]);
        // A v2 capability is of its own week, whenever it is presented.
        for now in [
            grid::week_start(p) - 86_400,
            grid::week_start(p + 1) + 3_599,
        ] {
            assert_eq!(capability_week(&v2, cap.expiry_unix, now), p);
        }
        assert_eq!(capability_serial(&v2), [0xAB; 16]);
        // A v1 capability is of the week of the registration.
        let v1 = key.mint(&cap);
        assert_eq!(
            capability_week(&v1, cap.expiry_unix, grid::week_start(p + 7) + 5),
            p + 7
        );
        assert_eq!(capability_serial(&v1), scope_hash(&v1)[..16]);
        assert_eq!(registration_valid_until(p), grid::week_start(p + 2) + 3_600);
        assert_eq!(registration_valid_until(u64::MAX), u64::MAX);
    }
}
