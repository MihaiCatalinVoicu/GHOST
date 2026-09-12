//! Relay redemption (Phase 8 design §10, ADR-25): `RedeemToken` turns a Privacy Pass type 0x0002
//! ACCESS token of the Entitlement Schedule (ES) into a write capability v2 for one namespace.
//!
//! - A token names one relay slot and one ISO week inside its blinded challenge, so it is valid at
//!   exactly the relay the ES lists for that slot in that week, and only inside the week's
//!   acceptance window `[start(p) - early_window, start(p + 1) + 1 h)`.
//! - The nullifier is computed here from the token, never read from the wire, and is persisted in
//!   `nullifiers.redb` with a binding tag before anything is minted; the minted capability is a
//!   pure function of the relay key, the week, the nullifier and the namespace, so an identical
//!   retry, even after a restart, receives identical bytes (MS-8).
//! - Invalid tokens are rejected before any disk write, and forged, wrong-kind and wrong-slot
//!   tokens get one answer (`PERMISSION_DENIED`, capture `rejected_token`): no oracle.
//!
//! [`Relay::redeem_at`] applies the checks in exactly the order of design §10.2 and records exactly
//! one capture event.

use std::path::Path;
use std::sync::{Arc, Mutex};

use ghost_entitlement::grid::{self, Kind as TokenKind};
use ghost_entitlement::onion::{parse_hostname, Onion};
use ghost_entitlement::schedule::ScheduleError;
use ghost_entitlement::token::TOKEN_LEN;
use ghost_entitlement::{Expect, Schedule, ScheduleMemory, Token};
use ghost_relay_api::proto::{
    Capability as CapabilityMessage, RedeemResult, RedeemTokenRequest, RedeemTokenResponse,
};
use ghost_relay_api::{time_bucket, HASH_BYTES, PROTOCOL_VERSION, REQUEST_ID_BYTES};
use ghost_relay_capability::{scope_hash, Capability, Kind};
use ghost_relay_storage::nullifiers::{EsMemory, NullifierStart, NullifierStore, Record};
use ghost_relay_storage::StoreError;
use tonic::Status;

use crate::capture::{hex_or_none, Event};
use crate::{fixed, Relay, REJECTED, UNAUTHORIZED};

/// File name of the nullifier store inside the data directory (design §10.4).
pub const NULLIFIERS_FILE: &str = "nullifiers.redb";

/// How the relay opens `nullifiers.redb` at start (design §10.5, §19.10 point 2, runbook O1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NullifierMode {
    /// The store must exist (a data directory whose `relay.key` already existed).
    Existing,
    /// A missing store is created empty: a fresh data directory, or the one-time Phase 8 upgrade
    /// of a relay that never redeemed (`--nullifiers-init`).
    Create,
    /// `--nullifiers-reset` after losing the store: every period whose acceptance window is open
    /// at the reset is refused (`UNAVAILABLE`) for good.
    Reset,
}

/// The global redemption token bucket (design §10.2 step 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedeemRate {
    pub per_second: u32,
    pub burst: u32,
}

impl Default for RedeemRate {
    fn default() -> Self {
        RedeemRate {
            per_second: 50,
            burst: 500,
        }
    }
}

/// What a relay needs to redeem tokens (design §10.5): the verified ES, its slot, its own onion
/// service key (from Tor's `HiddenServiceDir/hostname`, §19.10 point 3), how to open the nullifier
/// store, and the global rate.
pub struct EntitlementPolicy {
    pub schedule: Arc<Schedule>,
    pub slot: u8,
    pub onion: [u8; 32],
    pub nullifiers: NullifierMode,
    pub rate: RedeemRate,
}

impl EntitlementPolicy {
    /// A policy for `slot` (0..31) with the default rate and [`NullifierMode::Existing`].
    pub fn new(schedule: Schedule, slot: u8, onion: [u8; 32]) -> Result<Self, StartError> {
        if slot > ghost_entitlement::challenge::MAX_SLOT {
            return Err(StartError::Slot);
        }
        Ok(EntitlementPolicy {
            schedule: Arc::new(schedule),
            slot,
            onion,
            nullifiers: NullifierMode::Existing,
            rate: RedeemRate::default(),
        })
    }
}

/// The service key of the onion named by the contents of Tor's `HiddenServiceDir/hostname`: exactly
/// one canonical v3 host name, optionally followed by one newline (as Tor writes it).
pub fn onion_from_hostname_file(text: &str) -> Result<[u8; 32], StartError> {
    let host = text.strip_suffix('\n').unwrap_or(text);
    parse_hostname(host).map_err(|_| StartError::OnionHostname)
}

/// Why a relay with redemption enabled refuses to start (design §10.5). Every message is a
/// constant.
#[derive(Debug)]
pub enum StartError {
    /// The slot is above 31.
    Slot,
    /// The onion hostname file does not hold one canonical v3 host name.
    OnionHostname,
    /// The ES does not list this relay's onion for its slot in the current week.
    OnionNotListed,
    /// The ES is not append-only against the relay's memory (rule 5).
    Schedule(ScheduleError),
    /// The nullifier store is missing, of another schema, or unreadable.
    NullifierStore(StoreError),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::Slot => f.write_str("relay slot must be 0..31"),
            StartError::OnionHostname => {
                f.write_str("onion hostname file does not hold one canonical v3 host name")
            }
            StartError::OnionNotListed => f.write_str(
                "the schedule does not list this relay's onion for its slot in the current week",
            ),
            StartError::Schedule(e) => write!(f, "schedule refused: {e}"),
            StartError::NullifierStore(StoreError::Missing) => f.write_str(
                "nullifier store is missing: after a loss start with --nullifiers-reset (runbook O1)",
            ),
            StartError::NullifierStore(e) => write!(f, "nullifier store: {e}"),
        }
    }
}

impl std::error::Error for StartError {}

impl From<StoreError> for StartError {
    fn from(e: StoreError) -> Self {
        StartError::NullifierStore(e)
    }
}

/// The last access week whose acceptance window has closed at `now` (`now >= start(p + 1) + 1 h`),
/// or `None` before any has.
pub fn closed_through(now: u64) -> Option<u64> {
    let t = now.checked_sub(grid::LATE_WINDOW_SECS)?;
    if t < grid::week_start(1) {
        return None;
    }
    Some(grid::week(t) - 1)
}

/// Expiry of a capability redeemed for week `p`: `start(p + 1) + 3600`, the same for everyone
/// (design §10.3).
pub fn capability_expiry(p: u64) -> u64 {
    grid::week_start(p.saturating_add(1)).saturating_add(grid::LATE_WINDOW_SECS)
}

/// True iff the ES lists the onion with service key `onion` for `slot` in `week`.
fn listed(schedule: &Schedule, slot: u8, week: u64, onion: &[u8; 32]) -> bool {
    schedule
        .slot_onion(slot, week)
        .and_then(|o| Onion::parse(o).ok())
        .is_some_and(|o| o.pubkey == *onion)
}

/// The global token bucket, refilled per whole second of the handler's clock.
struct Bucket {
    tokens: u64,
    last: Option<u64>,
}

impl Bucket {
    fn take(&mut self, rate: &RedeemRate, now: u64) -> bool {
        let burst = u64::from(rate.burst);
        match self.last {
            None => {
                self.tokens = burst;
                self.last = Some(now);
            }
            Some(last) if now > last => {
                let refill = u64::from(rate.per_second).saturating_mul(now - last);
                self.tokens = burst.min(self.tokens.saturating_add(refill));
                self.last = Some(now);
            }
            Some(_) => {}
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

/// Redemption state of an open relay.
pub(crate) struct Redeem {
    schedule: Arc<Schedule>,
    slot: u8,
    onion: [u8; 32],
    rate: RedeemRate,
    bucket: Mutex<Bucket>,
    store: NullifierStore,
}

impl Redeem {
    /// The start-up checks of design §10.5, in this order: the onion is listed for the slot in
    /// the current week (before anything is written); the nullifier store opens as `nullifiers`
    /// says; the ES is append-only against the remembered facts (rule 5); then the ES's facts are
    /// remembered.
    pub(crate) fn open(
        policy: EntitlementPolicy,
        data_dir: &Path,
        now: u64,
    ) -> Result<Self, StartError> {
        let schedule = policy.schedule;
        if policy.slot > ghost_entitlement::challenge::MAX_SLOT {
            return Err(StartError::Slot);
        }
        if !listed(&schedule, policy.slot, grid::week(now), &policy.onion) {
            return Err(StartError::OnionNotListed);
        }
        let start = match policy.nullifiers {
            NullifierMode::Existing => NullifierStart::Existing,
            NullifierMode::Create => NullifierStart::Create,
            // The last period whose window is open now: p + 1 during the last early_window of
            // week p, otherwise p (design §19.10 point 2).
            NullifierMode::Reset => NullifierStart::Reset {
                refuse_through_period: grid::week(
                    now.saturating_add(u64::from(schedule.constants().early_window_hours) * 3_600),
                ),
            },
        };
        let store = NullifierStore::open(&data_dir.join(NULLIFIERS_FILE), start)?;
        schedule
            .check_memory(&schedule_memory(&store.es_memory()?)?)
            .map_err(StartError::Schedule)?;
        store.remember_es(&es_memory_of(&schedule))?;
        Ok(Redeem {
            schedule,
            slot: policy.slot,
            onion: policy.onion,
            rate: policy.rate,
            bucket: Mutex::new(Bucket {
                tokens: 0,
                last: None,
            }),
            store,
        })
    }

    pub(crate) fn store(&self) -> &NullifierStore {
        &self.store
    }
}

/// The relay's remembered facts as rule 5 reads them (the relay remembers keys, revocations and
/// `seq`; neither prices nor other slots, §19.2 point 2).
fn schedule_memory(memory: &EsMemory) -> Result<ScheduleMemory, StartError> {
    let kind = |b: u8| {
        TokenKind::from_byte(b).ok_or(StartError::NullifierStore(StoreError::IncompatibleSchema))
    };
    let mut out = ScheduleMemory {
        max_seq: memory.max_seq,
        ..ScheduleMemory::default()
    };
    for (&(k, epoch), id) in &memory.keys {
        out.keys.insert((kind(k)?, epoch), *id);
    }
    for &(k, epoch) in &memory.revoked {
        out.revoked.insert((kind(k)?, epoch));
    }
    Ok(out)
}

/// The facts of an accepted ES the relay remembers.
fn es_memory_of(schedule: &Schedule) -> EsMemory {
    EsMemory {
        max_seq: Some(schedule.seq()),
        keys: schedule
            .keys()
            .map(|k| ((k.kind.byte(), k.epoch), k.key_id))
            .collect(),
        revoked: schedule
            .content()
            .revoked
            .iter()
            .map(|(k, e)| (k.byte(), *e))
            .collect(),
    }
}

impl Relay {
    /// RedeemToken at time `now` (unix seconds): design §10.2, exactly one capture event
    /// (`op = "redeem"`; `period_id` once the key id names an ES ACCESS key, `nullifier` once the
    /// token verifies, `capability_scope` for `ok` only).
    pub fn redeem_at(
        &self,
        req: RedeemTokenRequest,
        now: u64,
    ) -> Result<RedeemTokenResponse, Status> {
        let mut event = Event {
            op: "redeem",
            protocol_version: PROTOCOL_VERSION,
            namespace_id: hex_or_none(&req.namespace_id, HASH_BYTES),
            time_bucket: time_bucket(now),
            request_id: hex_or_none(&req.request_id, REQUEST_ID_BYTES),
            result: "ok",
            ..Default::default()
        };
        let outcome = self.redeem_steps(&req, now, &mut event);
        self.record(event);
        outcome
    }

    fn redeem_steps(
        &self,
        req: &RedeemTokenRequest,
        now: u64,
        event: &mut Event,
    ) -> Result<RedeemTokenResponse, Status> {
        // Every response carries the relay's week and minute (R9 clock sources).
        let answer = |result: RedeemResult, capability: Option<Vec<u8>>| RedeemTokenResponse {
            result: result as i32,
            capability: capability.map(|token| CapabilityMessage { token }),
            relay_period_id: grid::week(now),
            relay_minute: now / 60,
        };
        let token_denied = || Status::permission_denied(UNAUTHORIZED);

        // 1. Redemption disabled (no --schedule).
        let Some(r) = &self.redeem else {
            event.result = "rejected_capability";
            return Err(Status::unimplemented(REJECTED));
        };
        // 2. Global token bucket.
        if !r.bucket.lock().unwrap().take(&r.rate, now) {
            event.result = "rejected_capability";
            return Err(Status::resource_exhausted(REJECTED));
        }
        // 3. Version and lengths.
        let namespace = match fixed::<32>(&req.namespace_id) {
            Some(ns)
                if req.version == PROTOCOL_VERSION
                    && req.token.len() == TOKEN_LEN
                    && req.request_id.len() == REQUEST_ID_BYTES =>
            {
                ns
            }
            _ => {
                event.result = "rejected_size";
                return Err(Status::invalid_argument(REJECTED));
            }
        };
        // 4. Type 0x0002; the key id names an ES ACCESS key of week p, not revoked; the ES lists
        //    this relay's onion for its slot in week p.
        let parsed = Token::parse(&req.token).ok().and_then(|token| {
            let key = r.schedule.key_by_id(token.key_id())?;
            (key.kind == TokenKind::Access).then_some((key.epoch, token))
        });
        let Some((p, token)) = parsed else {
            event.result = "rejected_token";
            return Err(token_denied());
        };
        event.period_id = Some(hex::encode(grid::epoch_id(p)));
        if r.schedule.is_revoked(TokenKind::Access, p) || !listed(&r.schedule, r.slot, p, &r.onion)
        {
            event.result = "rejected_token";
            return Err(token_denied());
        }
        // 5. Closed-period high-water and the acceptance window: WRONG_PERIOD, nothing recorded.
        //    After a store reset, the periods open at the reset are refused.
        let Ok(state) = r.store.state() else {
            event.result = "rejected_capability";
            return Err(Status::unavailable(REJECTED));
        };
        let early = r.schedule.constants().early_window_hours;
        if state.closed_through_period.is_some_and(|c| p <= c)
            || !grid::access_accepts(p, now, early)
        {
            event.result = "rejected_period";
            return Ok(answer(RedeemResult::WrongPeriod, None));
        }
        if state.refuse_through_period.is_some_and(|x| p <= x) {
            event.result = "rejected_capability";
            return Err(Status::unavailable(REJECTED));
        }
        // 6, 7. The challenge of (ACCESS, p, my slot), then `ring` verifies the authenticator.
        let nullifier = match r
            .schedule
            .verify_token(&token, Expect::AccessAtSlot(r.slot))
        {
            Ok(v) if v.epoch == p => v.nullifier,
            _ => {
                event.result = "rejected_token";
                return Err(token_denied());
            }
        };
        // 8. The nullifier (computed, never read from the wire) and the binding tag.
        event.nullifier = Some(hex::encode(nullifier));
        let tag = self
            .key
            .redeem_binding(p, &nullifier, Kind::Write, &namespace);
        // 9. Record or read the binding, committed (fsync) before minting.
        match r.store.record_or_get(p, &nullifier, &tag) {
            Ok(Record::Inserted | Record::Identical) => {}
            Ok(Record::Bound) => {
                event.result = "rejected_nullifier";
                return Ok(answer(RedeemResult::Replayed, None));
            }
            // A sweep closed the period between steps 5 and 9: the same answer as step 5.
            Ok(Record::Closed) => {
                event.result = "rejected_period";
                return Ok(answer(RedeemResult::WrongPeriod, None));
            }
            Ok(Record::Refused) | Err(_) => {
                event.result = "rejected_capability";
                return Err(Status::unavailable(REJECTED));
            }
        }
        // 10. Deterministic mint.
        let serial = self.key.capability_serial(p, &nullifier);
        let capability = self.key.mint_v2(
            &Capability {
                kind: Kind::Write,
                namespace,
                quota_bytes: r.schedule.constants().capability_quota_bytes,
                expiry_unix: capability_expiry(p),
            },
            &serial,
        );
        event.capability_scope = Some(hex::encode(scope_hash(&capability)));
        Ok(answer(RedeemResult::Ok, Some(capability)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_through_follows_the_one_hour_late_window() {
        assert_eq!(closed_through(0), None);
        assert_eq!(closed_through(grid::week_start(1) + 3_599), None);
        assert_eq!(closed_through(grid::week_start(1) + 3_600), Some(0));
        let p = 2959;
        assert_eq!(closed_through(grid::week_start(p + 1) + 3_599), Some(p - 1));
        assert_eq!(closed_through(grid::week_start(p + 1) + 3_600), Some(p));
        assert_eq!(capability_expiry(p), grid::week_start(p + 1) + 3_600);
        // A closed week is exactly one whose window no longer accepts.
        for t in [
            grid::week_start(p + 1) + 3_599,
            grid::week_start(p + 1) + 3_600,
        ] {
            let closed = closed_through(t).is_some_and(|c| p <= c);
            assert_eq!(closed, !grid::access_accepts(p, t, 24));
        }
    }

    #[test]
    fn the_bucket_admits_its_burst_then_its_rate() {
        let rate = RedeemRate {
            per_second: 2,
            burst: 3,
        };
        let mut b = Bucket {
            tokens: 0,
            last: None,
        };
        assert!((0..3).all(|_| b.take(&rate, 100)));
        assert!(!b.take(&rate, 100));
        // A clock stepped back refills nothing.
        assert!(!b.take(&rate, 99));
        assert!(b.take(&rate, 101) && b.take(&rate, 101));
        assert!(!b.take(&rate, 101));
        // Refill is capped at the burst.
        assert!((0..3).all(|_| b.take(&rate, 10_000)));
        assert!(!b.take(&rate, 10_000));
    }

    #[test]
    fn hostname_files_hold_exactly_one_host_name() {
        let key = [5u8; 32];
        let host = ghost_entitlement::onion::hostname(&key);
        assert_eq!(onion_from_hostname_file(&host).unwrap(), key);
        assert_eq!(onion_from_hostname_file(&format!("{host}\n")).unwrap(), key);
        for bad in [
            format!("{host}\n\n"),
            format!("{host}\r\n"),
            format!("{host}:443\n"),
            format!("\n{host}"),
            String::new(),
            "not an onion\n".to_string(),
        ] {
            assert!(onion_from_hostname_file(&bad).is_err(), "{bad:?}");
        }
    }
}
