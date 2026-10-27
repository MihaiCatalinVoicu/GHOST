//! Relay client bound to one namespace by type (Phase 7, invariant T21: isolation scope equals
//! capability scope).
//!
//! `GetBlobRequest` and `CheckBlobsRequest` carry no namespace: the relay takes it from the
//! capability. A caller that isolated a call under namespace A but passed a capability for
//! namespace B would send B's reads over A's circuits, linking the two namespaces at the relay.
//! [`NamespaceClient`] closes that: it is built only by [`NamespaceClient::over_tor`], which fixes
//! the circuit isolation to [`IsolationScope::Namespace`] of its namespace, its methods take no
//! namespace, and before any I/O every call parses the presented token and requires
//! - the token's namespace to equal the bound namespace, and
//! - its kind to fit the operation.
//!
//! Two token layouts pass that guard (Phase 9 design §4.3, §21.2 point 3, §22.8.7 point 1):
//! - a relay-minted capability ([`ghost_relay_api::capability_header`]): write for store, read or
//!   write for get, list and check (at the relay a write capability also grants read), and write
//!   for a key registration;
//! - a bearer credential v3 ([`ghost_relay_api::bearer_credential`]), whose kind names its
//!   operations exactly: read → get, list, check; deposit → store, check; fetch → get, list. A
//!   credential registers nothing. Its slot is the relay's business, not the client's (§21.2
//!   point 3): the client cannot know which slot a relay holds this week.
//!
//! Anything else, including a token whose format this build cannot parse, fails with
//! [`RelayError::InvalidArgument`] (category `invalid_argument`) without opening a connection.
//!
//! [`NamespaceClient::redeem`] exchanges an entitlement token for a write capability of the bound
//! namespace (Phase 8 design §10.9), on the namespace's own circuits: the relay links the
//! redemption to the namespace anyway by minting for it. It binds with the Entitlement Schedule
//! built into the library and takes no schedule of the caller's. Before any I/O the token must be
//! an ACCESS token of that ES whose challenge names a slot the ES assigns to *this* relay in the
//! token's week ([`redeem_binding`]), so a token bound elsewhere never leaves the device (0
//! requests, 0 connections; mutant M6). The answer is checked against the ES ([`redeem_with`]).
//!
//! [`NamespaceClient::register_key`] registers, with a usable write capability of the bound
//! namespace, the verifier of a bearer secret for one ISO week (Phase 9 design §4.4): the
//! credentials v3 of that secret may then use the namespace at that relay until
//! `start(period + 2) + 1 h`. The secret itself never reaches the relay. `WRONG_PERIOD` is an
//! in-band answer (the period is judged by the capability's week, never by a clock); an `OK`
//! whose `valid_until_unix` is not the period's is [`RelayError::Malformed`].

use crate::entitlement::embedded_schedule;
use crate::isolation::IsolationScope;
use crate::onion::OnionAddress;
use crate::relay_client::{
    now_unix, BoxError, FetchedBlob, Io, OnionConnector, RelayClient, RelayError, StoreReceipt,
    StreamType,
};
use crate::transport::TorTransport;
use ghost_entitlement::grid::{self, LATE_WINDOW_SECS};
use ghost_entitlement::onion::{parse_hostname, Onion};
use ghost_entitlement::{Expect, Kind, Schedule, Token};
use ghost_relay_api::proto::{
    Capability, RedeemResult, RedeemTokenRequest, RedeemTokenResponse, RegisterKeyRequest,
    RegisterKeyResponse, RegisterResult,
};
use ghost_relay_api::{
    bearer_credential, capability_format, capability_header, BearerKind, CapabilityFormat,
    CapabilityKind, PROTOCOL_VERSION, REQUEST_ID_BYTES, VERIFIER_BYTES,
};
use std::fmt;
use std::future::Future;
use std::time::Duration;

/// The operation a token must authorize. The relay applies the same matrix (Phase 9 design §4.3,
/// §4.5); this client applies it before any I/O, so a token that does not fit never leaves the
/// device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// Store: a write capability, or a deposit credential.
    Store,
    /// Get: a read or write capability, or a read or fetch credential.
    Get,
    /// List: a read or write capability, or a read or fetch credential.
    List,
    /// Check: a read or write capability, or a read or deposit credential.
    Check,
    /// `RegisterKey`: a write capability only. A bearer credential registers nothing (its own
    /// authority is a registration, §4.4 point 2).
    Register,
}

/// A relay client whose every call is scoped to one namespace (see the module docs).
pub struct NamespaceClient<C> {
    inner: RelayClient<C>,
    namespace: [u8; 32],
    /// The relay this client talks to (the redemption check needs its onion).
    relay: OnionAddress,
}

impl NamespaceClient<OnionConnector> {
    /// Client for `relay` over Tor on the circuits of `IsolationScope::Namespace(namespace)`. No
    /// connection is opened until the first accepted call. This is the only public constructor.
    pub fn over_tor(transport: &TorTransport, relay: &OnionAddress, namespace: [u8; 32]) -> Self {
        NamespaceClient {
            inner: RelayClient::over_tor(transport, relay, &IsolationScope::Namespace(namespace)),
            namespace,
            relay: relay.clone(),
        }
    }
}

impl<C> NamespaceClient<C>
where
    C: tower::Service<http::Uri, Response = Io<C::Stream>> + Clone + Send + Sync + 'static,
    C: StreamType,
    C::Future: Unpin + Send,
    C::Error: Into<BoxError>,
{
    /// In-process constructor over another connector (loopback relays; G-D11's wire-transcript
    /// generator drives the namespace RPCs through this seam instead of Tor).
    pub fn with_connector(connector: C, relay: OnionAddress, namespace: [u8; 32]) -> Self {
        NamespaceClient {
            inner: RelayClient::with_connector(connector),
            namespace,
            relay,
        }
    }

    /// The namespace every call of this client is bound to.
    pub fn namespace(&self) -> &[u8; 32] {
        &self.namespace
    }

    /// Sets the deadline of every later call to `min(deadline, RELAY_RPC_DEADLINE)`; a zero
    /// deadline is refused with [`RelayError::InvalidArgument`].
    pub fn set_deadline(&mut self, deadline: Duration) -> Result<(), RelayError> {
        self.inner.set_deadline(deadline)
    }

    /// The T21 guard: the token must name this client's namespace and fit the operation. A
    /// bearer credential v3 is read by its own parser (67 bytes, version 3, a known kind), so a
    /// credential of the wrong length, version or kind is refused here, like every other token
    /// this build cannot parse.
    fn authorize(&self, token: &[u8], access: Access) -> Result<(), RelayError> {
        if let Some(credential) = bearer_credential(token) {
            let kind_fits = matches!(
                (credential.kind, access),
                (BearerKind::Read, Access::Get | Access::List | Access::Check)
                    | (BearerKind::Deposit, Access::Store | Access::Check)
                    | (BearerKind::Fetch, Access::Get | Access::List)
            );
            if credential.namespace != self.namespace || !kind_fits {
                return Err(RelayError::InvalidArgument);
            }
            return Ok(());
        }
        let header = capability_header(token).ok_or(RelayError::InvalidArgument)?;
        let kind_fits = match access {
            Access::Store | Access::Register => header.kind == CapabilityKind::Write,
            Access::Get | Access::List | Access::Check => {
                matches!(header.kind, CapabilityKind::Read | CapabilityKind::Write)
            }
        };
        if header.namespace != self.namespace || !kind_fits {
            return Err(RelayError::InvalidArgument);
        }
        Ok(())
    }

    /// Stores an already-encrypted, bucket-sized blob in the bound namespace (a write capability,
    /// or a deposit credential v3).
    pub async fn store(
        &mut self,
        capability: Vec<u8>,
        ciphertext: Vec<u8>,
        ttl_seconds: u32,
    ) -> Result<StoreReceipt, RelayError> {
        self.authorize(&capability, Access::Store)?;
        self.inner
            .store(self.namespace, capability, ciphertext, ttl_seconds)
            .await
    }

    /// Fetches a blob of the bound namespace with its relay expiry (a read or write capability, or
    /// a read or fetch credential v3; a fetch credential gets week-coarse times, §22.8.7).
    pub async fn get(
        &mut self,
        capability: Vec<u8>,
        blob_hash: [u8; 32],
    ) -> Result<FetchedBlob, RelayError> {
        self.authorize(&capability, Access::Get)?;
        self.inner.get(blob_hash, capability).await
    }

    /// Lists one page of the bound namespace (a read or write capability, or a read or fetch
    /// credential v3). The returned cursor is empty (listing complete) or 8 opaque bytes.
    pub async fn list(
        &mut self,
        capability: Vec<u8>,
        cursor: Vec<u8>,
        limit: u32,
    ) -> Result<(Vec<[u8; 32]>, Vec<u8>), RelayError> {
        self.authorize(&capability, Access::List)?;
        self.inner
            .list(self.namespace, capability, cursor, limit)
            .await
    }

    /// Returns which of `hashes` (distinct) the relay holds in the bound namespace (a read or
    /// write capability, or a read or deposit credential v3: senders verify their own copies);
    /// the answer is a subset of the request, each hash at most once.
    pub async fn check(
        &mut self,
        capability: Vec<u8>,
        hashes: Vec<[u8; 32]>,
    ) -> Result<Vec<[u8; 32]>, RelayError> {
        self.authorize(&capability, Access::Check)?;
        self.inner.check(capability, hashes).await
    }

    /// Redeems an entitlement token for a write capability of the bound namespace at this relay
    /// (design §10.9): [`redeem_with`] under the Entitlement Schedule built into the library
    /// ([`embedded_schedule`]) and the device clock. It takes no schedule, so no caller can bind a
    /// token to another relay; a schedule that fails verification is
    /// [`RelayError::InvalidArgument`], with nothing sent. An identical retry (same token,
    /// namespace and `request_id`) gets the identical capability; `REPLAYED` and `WRONG_PERIOD`
    /// are in-band answers.
    pub async fn redeem(
        &mut self,
        token: &[u8],
        request_id: [u8; REQUEST_ID_BYTES],
    ) -> Result<RedeemOutcome, RelayError> {
        let schedule = embedded_schedule().map_err(|_| RelayError::InvalidArgument)?;
        let relay = self.relay.clone();
        let namespace = self.namespace;
        redeem_with(
            &mut self.inner,
            schedule,
            &relay,
            namespace,
            token,
            request_id,
            now_unix(),
        )
        .await
    }

    /// Registers `verifier` for `period_id` and `kind` in the bound namespace with `capability`
    /// (design §4.4), on the namespace's own circuits. Before any I/O the capability must be a
    /// write capability of this namespace (T21), so a capability of another namespace never
    /// leaves the device. An identical retry (same capability, period, kind, verifier) is
    /// idempotent at the relay. `WRONG_PERIOD` is an in-band answer.
    pub async fn register_key(
        &mut self,
        capability: Vec<u8>,
        period_id: u64,
        kind: BearerKind,
        verifier: [u8; VERIFIER_BYTES],
        request_id: [u8; REQUEST_ID_BYTES],
    ) -> Result<RegisterOutcome, RelayError> {
        self.authorize(&capability, Access::Register)?;
        let namespace = self.namespace;
        register_with(
            &mut self.inner,
            namespace,
            capability,
            period_id,
            kind,
            verifier,
            request_id,
            now_unix(),
        )
        .await
    }
}

/// The `RedeemToken` RPC (design §10.1). The relay client implements it over Tor; the checks of
/// [`redeem_with`] run against any implementation.
pub trait RedeemRpc {
    fn redeem_token(
        &mut self,
        req: RedeemTokenRequest,
    ) -> impl Future<Output = Result<RedeemTokenResponse, RelayError>> + Send;
}

impl<C> RedeemRpc for RelayClient<C>
where
    C: tower::Service<http::Uri, Response = Io<C::Stream>> + Clone + Send + Sync + 'static,
    C: StreamType,
    C::Future: Unpin + Send,
    C::Error: Into<BoxError>,
{
    fn redeem_token(
        &mut self,
        req: RedeemTokenRequest,
    ) -> impl Future<Output = Result<RedeemTokenResponse, RelayError>> + Send {
        self.redeem_raw(req)
    }
}

/// Where a token may be redeemed: its week and the slot this relay holds in that week.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedeemBinding {
    pub week: u64,
    pub slot: u8,
}

/// The pre-I/O check of a redemption (design §10.9, mutant M6): the token is 354 bytes of type
/// 0x0002 under an ES ACCESS key of week p, it verifies for (ACCESS, p, s) (challenge, `ring`, not
/// revoked), and s is a slot of `relay` in week p: a slot the ES lists under `relay`'s exact
/// address (onion and port), or, if none is, the one slot listed under its service key. Anything
/// else is [`RelayError::InvalidArgument`]: the token never leaves the device.
pub fn redeem_binding(
    schedule: &Schedule,
    relay: &OnionAddress,
    token: &[u8],
) -> Result<RedeemBinding, RelayError> {
    let token = Token::parse(token).map_err(|_| RelayError::InvalidArgument)?;
    let key = schedule
        .key_by_id(token.key_id())
        .ok_or(RelayError::InvalidArgument)?;
    if key.kind != Kind::Access {
        return Err(RelayError::InvalidArgument);
    }
    let week = key.epoch;
    // The challenge names one slot, so at most one candidate verifies.
    let slot = relay_slots(schedule, relay, week)?
        .into_iter()
        .find(|&s| {
            schedule
                .verify_token(&token, Expect::AccessAtSlot(s))
                .is_ok()
        })
        .ok_or(RelayError::InvalidArgument)?;
    Ok(RedeemBinding { week, slot })
}

/// The slots `relay` holds in `week`: those the ES lists under its exact address (onion and port),
/// or, if none is, the one slot listed under its service key. Relays match their own onion by
/// service key (§19.21 point 2), so one onion service may front relays of several slots on
/// different ports; an unlisted port of such a service names no slot, since which relay answers
/// there is unknown.
fn relay_slots(
    schedule: &Schedule,
    relay: &OnionAddress,
    week: u64,
) -> Result<Vec<u8>, RelayError> {
    let relay_key = parse_hostname(relay.host()).map_err(|_| RelayError::InvalidArgument)?;
    let listed: Vec<(u8, u16)> = schedule
        .slots_in_week(week)
        .into_iter()
        .filter_map(|s| {
            let onion = Onion::parse(schedule.slot_onion(s, week)?).ok()?;
            (onion.pubkey == relay_key).then_some((s, onion.port))
        })
        .collect();
    let exact: Vec<u8> = listed
        .iter()
        .filter(|&&(_, port)| port == relay.port())
        .map(|&(s, _)| s)
        .collect();
    Ok(match listed.as_slice() {
        _ if !exact.is_empty() => exact,
        [(only, _)] => vec![*only],
        _ => Vec::new(),
    })
}

/// A validated `RedeemToken` answer.
#[derive(Clone, PartialEq, Eq)]
pub struct RedeemOutcome {
    pub result: RedeemResult,
    /// The relay's week and minute (relay-facing clock source only, §12.5; never an input to
    /// issuer-facing decisions, §19.4).
    pub relay_period_id: u64,
    pub relay_minute: u64,
    /// OK only: the capability's expiry, `start(week + 1) + 1 h`; 0 otherwise.
    pub expiry_unix: u64,
    /// OK only: the minted write capability v2 (98 bytes), a bearer secret.
    pub capability: Option<Vec<u8>>,
}

impl RedeemOutcome {
    /// `result(1) || relay_period(8) || relay_minute(8) || expiry(8) || capability(98 or 0)`:
    /// what `Capabilities.put` needs; Kotlin never parses the capability.
    pub fn pack(&self) -> Vec<u8> {
        let cap = self.capability.as_deref().unwrap_or_default();
        let mut out = Vec::with_capacity(25 + cap.len());
        out.push(self.result as i32 as u8);
        out.extend_from_slice(&self.relay_period_id.to_be_bytes());
        out.extend_from_slice(&self.relay_minute.to_be_bytes());
        out.extend_from_slice(&self.expiry_unix.to_be_bytes());
        out.extend_from_slice(cap);
        out
    }
}

impl fmt::Debug for RedeemOutcome {
    // The capability is a bearer secret: never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RedeemOutcome({:?}, ..)", self.result)
    }
}

/// Redeems `token` for `namespace` at `relay` over `rpc` (design §10.9): [`redeem_binding`] before
/// any I/O, then the answer must fit it. Every answer carries `relay_period_id` within one week of
/// the client's week (from `client_now`) and a `relay_minute` inside that week. `OK` carries a v2
/// write capability for exactly this namespace, with the ES quota and the expiry
/// `start(p + 1) + 1 h` of the token's week p; `REPLAYED` and `WRONG_PERIOD` carry none. Anything
/// else is [`RelayError::Malformed`].
pub async fn redeem_with<R: RedeemRpc>(
    rpc: &mut R,
    schedule: &Schedule,
    relay: &OnionAddress,
    namespace: [u8; 32],
    token: &[u8],
    request_id: [u8; REQUEST_ID_BYTES],
    client_now: u64,
) -> Result<RedeemOutcome, RelayError> {
    let binding = redeem_binding(schedule, relay, token)?;
    let answer = rpc
        .redeem_token(RedeemTokenRequest {
            version: PROTOCOL_VERSION,
            token: token.to_vec(),
            namespace_id: namespace.to_vec(),
            request_id: request_id.to_vec(),
        })
        .await?;
    check_redeem(
        schedule,
        &binding,
        &namespace,
        answer,
        grid::week(client_now),
    )
}

fn check_redeem(
    schedule: &Schedule,
    binding: &RedeemBinding,
    namespace: &[u8; 32],
    r: RedeemTokenResponse,
    client_week: u64,
) -> Result<RedeemOutcome, RelayError> {
    let period = r.relay_period_id;
    let minute_week = r.relay_minute.checked_mul(60).map(grid::week);
    if period.abs_diff(client_week) > 1 || minute_week != Some(period) {
        return Err(RelayError::Malformed);
    }
    let result = RedeemResult::try_from(r.result).map_err(|_| RelayError::Malformed)?;
    let (capability, expiry_unix) = match result {
        RedeemResult::Ok => {
            let cap = r.capability.ok_or(RelayError::Malformed)?.token;
            let expiry =
                grid::week_start(binding.week.saturating_add(1)).saturating_add(LATE_WINDOW_SECS);
            let header = capability_header(&cap).ok_or(RelayError::Malformed)?;
            if capability_format(&cap) != Some(CapabilityFormat::V2)
                || header.kind != CapabilityKind::Write
                || header.namespace != *namespace
                || header.quota_bytes != schedule.constants().capability_quota_bytes
                || header.expiry_unix != expiry
            {
                return Err(RelayError::Malformed);
            }
            (Some(cap), expiry)
        }
        RedeemResult::Replayed | RedeemResult::WrongPeriod if r.capability.is_none() => (None, 0),
        _ => return Err(RelayError::Malformed),
    };
    Ok(RedeemOutcome {
        result,
        relay_period_id: period,
        relay_minute: r.relay_minute,
        expiry_unix,
        capability,
    })
}

/// The `RegisterKey` RPC (Phase 9 design §4.2). The relay client implements it over Tor; the
/// checks of [`register_with`] run against any implementation.
pub trait RegisterRpc {
    fn register_key(
        &mut self,
        req: RegisterKeyRequest,
    ) -> impl Future<Output = Result<RegisterKeyResponse, RelayError>> + Send;
}

impl<C> RegisterRpc for RelayClient<C>
where
    C: tower::Service<http::Uri, Response = Io<C::Stream>> + Clone + Send + Sync + 'static,
    C: StreamType,
    C::Future: Unpin + Send,
    C::Error: Into<BoxError>,
{
    fn register_key(
        &mut self,
        req: RegisterKeyRequest,
    ) -> impl Future<Output = Result<RegisterKeyResponse, RelayError>> + Send {
        self.register_raw(req)
    }
}

/// When a registration of `period` lapses: `start(period + 2) + 1 h` (design §4.4 point 4). The
/// client computes it from the period it asked for, so a relay cannot claim a longer validity and
/// keep the owner from registering again (§4.8 healing rule).
pub fn registration_valid_until(period: u64) -> u64 {
    grid::week_start(period.saturating_add(2)).saturating_add(LATE_WINDOW_SECS)
}

/// A validated `RegisterKey` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterOutcome {
    pub result: RegisterResult,
    /// The relay's week and minute (relay-facing clock source only, §19.4).
    pub relay_period_id: u64,
    pub relay_minute: u64,
    /// OK only: `start(period + 2) + 1 h`, the instant the relay forgets the record; 0 otherwise.
    pub valid_until_unix: u64,
}

impl RegisterOutcome {
    /// `result(1) || relay_period(8) || relay_minute(8) || valid_until(8)`: what the registration
    /// row needs (design §4.8). 25 bytes, whatever the result.
    pub fn pack(&self) -> [u8; 25] {
        let mut out = [0u8; 25];
        out[0] = self.result as i32 as u8;
        out[1..9].copy_from_slice(&self.relay_period_id.to_be_bytes());
        out[9..17].copy_from_slice(&self.relay_minute.to_be_bytes());
        out[17..25].copy_from_slice(&self.valid_until_unix.to_be_bytes());
        out
    }
}

/// Registers `verifier` for `(namespace, period_id, kind)` with `capability` over `rpc` (design
/// §4.4). Every answer carries `relay_period_id` within one week of the client's week (from
/// `client_now`) and a `relay_minute` inside that week. `OK` carries the period's
/// [`registration_valid_until`]; `WRONG_PERIOD` carries none. Anything else is
/// [`RelayError::Malformed`].
#[allow(clippy::too_many_arguments)]
pub async fn register_with<R: RegisterRpc>(
    rpc: &mut R,
    namespace: [u8; 32],
    capability: Vec<u8>,
    period_id: u64,
    kind: BearerKind,
    verifier: [u8; VERIFIER_BYTES],
    request_id: [u8; REQUEST_ID_BYTES],
    client_now: u64,
) -> Result<RegisterOutcome, RelayError> {
    let answer = rpc
        .register_key(RegisterKeyRequest {
            version: PROTOCOL_VERSION,
            namespace_id: namespace.to_vec(),
            period_id,
            kind: i32::from(kind.byte()),
            verifier: verifier.to_vec(),
            capability: Some(Capability { token: capability }),
            request_id: request_id.to_vec(),
        })
        .await?;
    check_register(period_id, answer, grid::week(client_now))
}

fn check_register(
    period_id: u64,
    r: RegisterKeyResponse,
    client_week: u64,
) -> Result<RegisterOutcome, RelayError> {
    let period = r.relay_period_id;
    let minute_week = r.relay_minute.checked_mul(60).map(grid::week);
    if period.abs_diff(client_week) > 1 || minute_week != Some(period) {
        return Err(RelayError::Malformed);
    }
    let result = RegisterResult::try_from(r.result).map_err(|_| RelayError::Malformed)?;
    let valid_until_unix = match result {
        RegisterResult::Ok if r.valid_until_unix == registration_valid_until(period_id) => {
            r.valid_until_unix
        }
        RegisterResult::WrongPeriod if r.valid_until_unix == 0 => 0,
        _ => return Err(RelayError::Malformed),
    };
    Ok(RegisterOutcome {
        result,
        relay_period_id: period,
        relay_minute: r.relay_minute,
        valid_until_unix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loopback::TcpConnector;
    use ghost_relay_api::proto::relay_service_server::{RelayService, RelayServiceServer};
    use ghost_relay_api::proto::*;
    use ghost_relay_api::{BearerCredential, CapabilityHeader, CAPABILITY_MAC_BYTES};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;

    const NS_A: [u8; 32] = [0xA1; 32];
    const NS_B: [u8; 32] = [0xB2; 32];

    fn relay_onion() -> OnionAddress {
        OnionAddress::parse("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443")
            .unwrap()
    }

    /// A token with a v1 header; the MAC is irrelevant to the client-side guard.
    fn token(kind: CapabilityKind, namespace: [u8; 32]) -> Vec<u8> {
        let mut t = CapabilityHeader {
            kind,
            namespace,
            quota_bytes: 1 << 20,
            expiry_unix: u64::MAX,
        }
        .encode_body()
        .to_vec();
        t.extend_from_slice(&[0x33; CAPABILITY_MAC_BYTES]);
        t
    }

    /// A token with a v2 header (a redeemed write capability, Phase 8 design §10.3).
    fn token_v2(kind: CapabilityKind, namespace: [u8; 32]) -> Vec<u8> {
        let mut t = CapabilityHeader {
            kind,
            namespace,
            quota_bytes: 1 << 28,
            expiry_unix: u64::MAX,
        }
        .encode_body_v2(&[0x44; 16])
        .to_vec();
        t.extend_from_slice(&[0x33; CAPABILITY_MAC_BYTES]);
        t
    }

    /// A bearer credential v3 (Phase 9 design §4.3). The secret is arbitrary: the client-side
    /// guard reads the version, kind and namespace only.
    fn credential(kind: BearerKind, namespace: [u8; 32]) -> Vec<u8> {
        BearerCredential {
            kind,
            slot: 7,
            namespace,
            secret: [0x5C; 32],
        }
        .encode()
        .to_vec()
    }

    /// Every operation a client may present a token for.
    const EVERY_ACCESS: [Access; 5] = [
        Access::Store,
        Access::Get,
        Access::List,
        Access::Check,
        Access::Register,
    ];

    /// Tokens the guard must refuse for a client bound to `NS_A`, whatever the operation.
    fn refused_for_every_operation() -> Vec<(&'static str, Vec<u8>)> {
        let good = token(CapabilityKind::Write, NS_A);
        let mut version2 = good.clone();
        version2[0] = 2;
        let mut kind0 = good.clone();
        kind0[1] = 0;
        let mut kind3 = good.clone();
        kind3[1] = 3;
        let mut longer = good.clone();
        longer.push(0);
        let mut v2_as_v1 = token_v2(CapabilityKind::Write, NS_A);
        v2_as_v1[0] = 1;
        // Credential v3 rows (§21.2 point 12, §22.8.7 point 1): wrong namespace, lengths 66 and
        // 68, the unknown kind 0x02 (Write in a capability header, never a bearer kind) and a
        // version this build does not know.
        let deposit = credential(BearerKind::Deposit, NS_A);
        let mut kind_two = deposit.clone();
        kind_two[1] = 2;
        let mut kind_zero = deposit.clone();
        kind_zero[1] = 0;
        let mut version4 = deposit.clone();
        version4[0] = 4;
        let mut sixty_eight = deposit.clone();
        sixty_eight.push(0);
        vec![
            ("empty", Vec::new()),
            ("truncated", good[..good.len() - 1].to_vec()),
            ("longer", longer),
            ("version 2", version2),
            ("v2 length with version 1", v2_as_v1),
            (
                "v2 write for another namespace",
                token_v2(CapabilityKind::Write, NS_B),
            ),
            ("kind 0", kind0),
            ("kind 3", kind3),
            (
                "read for another namespace",
                token(CapabilityKind::Read, NS_B),
            ),
            (
                "write for another namespace",
                token(CapabilityKind::Write, NS_B),
            ),
            (
                "deposit credential for another namespace",
                credential(BearerKind::Deposit, NS_B),
            ),
            (
                "read credential for another namespace",
                credential(BearerKind::Read, NS_B),
            ),
            (
                "fetch credential for another namespace",
                credential(BearerKind::Fetch, NS_B),
            ),
            ("credential of 66 bytes", deposit[..66].to_vec()),
            ("credential of 68 bytes", sixty_eight),
            ("credential kind 0x02", kind_two),
            ("credential kind 0x00", kind_zero),
            ("credential version 4", version4),
        ]
    }

    #[tokio::test]
    async fn the_guard_accepts_only_this_namespace_and_a_fitting_kind() {
        let client = NamespaceClient::with_connector(
            TcpConnector::new("127.0.0.1:9".parse().unwrap()),
            relay_onion(),
            NS_A,
        );
        assert_eq!(client.namespace(), &NS_A);
        let read = token(CapabilityKind::Read, NS_A);
        let write = token(CapabilityKind::Write, NS_A);
        assert!(client.authorize(&write, Access::Store).is_ok());
        assert!(
            client.authorize(&write, Access::Get).is_ok(),
            "write grants read"
        );
        assert!(client.authorize(&write, Access::Register).is_ok());
        assert!(client.authorize(&read, Access::Get).is_ok());
        for access in [Access::Store, Access::Register] {
            assert!(
                matches!(
                    client.authorize(&read, access),
                    Err(RelayError::InvalidArgument)
                ),
                "read never grants write ({access:?})"
            );
        }
        // A redeemed (v2) write capability for this namespace passes the same guard.
        let redeemed = token_v2(CapabilityKind::Write, NS_A);
        assert!(client.authorize(&redeemed, Access::Store).is_ok());
        assert!(client.authorize(&redeemed, Access::Get).is_ok());
        for (why, t) in refused_for_every_operation() {
            for access in EVERY_ACCESS {
                assert!(
                    matches!(
                        client.authorize(&t, access),
                        Err(RelayError::InvalidArgument)
                    ),
                    "{why} / {access:?}"
                );
            }
        }
        assert_eq!(
            crate::categories::for_relay(&RelayError::InvalidArgument),
            crate::categories::INVALID_ARGUMENT
        );
    }

    /// The kind/operation matrix of a credential v3 (design §4.3 "Rights", §4.5, §22.8.7 point 1),
    /// exactly as the relay applies it (`relay/crates/node/src/bearer.rs::allows`), plus the rule
    /// that no credential registers a key (§4.4 point 2).
    #[tokio::test]
    async fn the_credential_matrix_is_the_relay_s() {
        let client = NamespaceClient::with_connector(
            TcpConnector::new("127.0.0.1:9".parse().unwrap()),
            relay_onion(),
            NS_A,
        );
        let allowed = |kind| {
            EVERY_ACCESS
                .into_iter()
                .filter(|&access| client.authorize(&credential(kind, NS_A), access).is_ok())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            allowed(BearerKind::Read),
            [Access::Get, Access::List, Access::Check]
        );
        assert_eq!(allowed(BearerKind::Deposit), [Access::Store, Access::Check]);
        assert_eq!(allowed(BearerKind::Fetch), [Access::Get, Access::List]);
    }

    /// A relay that answers every request with success and counts what reaches it. It checks no
    /// capability at all, so the client-side guard is the only thing between a mismatched call
    /// and an answer: the counter shows whether a request was sent.
    #[derive(Clone)]
    struct CountingRelay {
        requests: Arc<AtomicUsize>,
        blob: Vec<u8>,
    }

    impl CountingRelay {
        fn count(&self) {
            self.requests.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tonic::async_trait]
    impl RelayService for CountingRelay {
        async fn store_blob(
            &self,
            r: tonic::Request<StoreBlobRequest>,
        ) -> Result<tonic::Response<StoreBlobResponse>, tonic::Status> {
            self.count();
            let r = r.into_inner();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Ok(tonic::Response::new(StoreBlobResponse {
                success: true,
                stored_hash: r.blob_hash,
                expiry_unix_seconds: now + u64::from(r.ttl_seconds),
            }))
        }
        async fn get_blob(
            &self,
            _r: tonic::Request<GetBlobRequest>,
        ) -> Result<tonic::Response<GetBlobResponse>, tonic::Status> {
            self.count();
            Ok(tonic::Response::new(GetBlobResponse {
                data: self.blob.clone(),
                ..Default::default()
            }))
        }
        async fn check_blobs(
            &self,
            r: tonic::Request<CheckBlobsRequest>,
        ) -> Result<tonic::Response<CheckBlobsResponse>, tonic::Status> {
            self.count();
            Ok(tonic::Response::new(CheckBlobsResponse {
                available_hashes: r.into_inner().blob_hashes,
            }))
        }
        async fn list_namespace(
            &self,
            _r: tonic::Request<ListNamespaceRequest>,
        ) -> Result<tonic::Response<ListNamespaceResponse>, tonic::Status> {
            self.count();
            Ok(tonic::Response::new(ListNamespaceResponse {
                blob_hashes: vec![Sha256::digest(&self.blob).to_vec()],
                next_cursor: vec![],
            }))
        }
        type GossipSyncStream = tokio_stream::Empty<Result<GossipAck, tonic::Status>>;
        async fn gossip_sync(
            &self,
            _r: tonic::Request<tonic::Streaming<GossipInventoryBatch>>,
        ) -> Result<tonic::Response<Self::GossipSyncStream>, tonic::Status> {
            self.count();
            Err(tonic::Status::unimplemented("gossip"))
        }
        async fn redeem_token(
            &self,
            r: tonic::Request<RedeemTokenRequest>,
        ) -> Result<tonic::Response<RedeemTokenResponse>, tonic::Status> {
            self.count();
            // Echoes the week of the device clock and answers REPLAYED (no capability).
            let now = now_unix();
            let _ = r.into_inner();
            Ok(tonic::Response::new(RedeemTokenResponse {
                result: RedeemResult::Replayed as i32,
                capability: None,
                relay_period_id: grid::week(now),
                relay_minute: now / 60,
            }))
        }
        async fn register_key(
            &self,
            r: tonic::Request<RegisterKeyRequest>,
        ) -> Result<tonic::Response<RegisterKeyResponse>, tonic::Status> {
            self.count();
            // Echoes the week of the device clock and records nothing (WRONG_PERIOD).
            let now = now_unix();
            let _ = r.into_inner();
            Ok(tonic::Response::new(RegisterKeyResponse {
                result: RegisterResult::WrongPeriod as i32,
                relay_period_id: grid::week(now),
                relay_minute: now / 60,
                valid_until_unix: 0,
            }))
        }
    }

    async fn counting_relay(blob: Vec<u8>) -> (CountingRelay, std::net::SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay = CountingRelay {
            requests: Arc::new(AtomicUsize::new(0)),
            blob,
        };
        let svc = RelayServiceServer::new(relay.clone());
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(svc)
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        (relay, addr)
    }

    #[tokio::test]
    async fn a_mismatched_capability_never_reaches_the_relay() {
        let blob = vec![0x6B; 4096];
        let hash: [u8; 32] = Sha256::digest(&blob).into();
        let (relay, addr) = counting_relay(blob.clone()).await;
        let connector = TcpConnector::new(addr);
        let mut client = NamespaceClient::with_connector(connector.clone(), relay_onion(), NS_A);

        let refused = refused_for_every_operation();
        let read_a = token(CapabilityKind::Read, NS_A);
        let deposit_a = credential(BearerKind::Deposit, NS_A);
        let read_key_a = credential(BearerKind::Read, NS_A);
        let fetch_a = credential(BearerKind::Fetch, NS_A);
        // Rows refused by one operation only: the kind/operation matrix of §4.3 and §22.8.7.
        let store_only = [
            ("read capability", read_a.clone()),
            ("read credential", read_key_a.clone()),
            ("fetch credential", fetch_a.clone()),
        ];
        let get_only = [("deposit credential", deposit_a.clone())];
        let list_only = [("deposit credential", deposit_a.clone())];
        let check_only = [("fetch credential", fetch_a.clone())];
        let register_only = [
            ("read capability", read_a.clone()),
            ("deposit credential", deposit_a.clone()),
            ("read credential", read_key_a.clone()),
            ("fetch credential", fetch_a.clone()),
        ];
        for (why, t) in refused.iter().chain(store_only.iter()) {
            let r = client.store(t.clone(), blob.clone(), 86_400).await;
            assert!(
                matches!(r, Err(RelayError::InvalidArgument)),
                "store {why}: {r:?}"
            );
        }
        for (why, t) in refused.iter().chain(get_only.iter()) {
            let r = client.get(t.clone(), hash).await;
            assert!(
                matches!(r, Err(RelayError::InvalidArgument)),
                "get {why}: {r:?}"
            );
        }
        for (why, t) in refused.iter().chain(list_only.iter()) {
            let r = client.list(t.clone(), vec![], 16).await;
            assert!(
                matches!(r, Err(RelayError::InvalidArgument)),
                "list {why}: {r:?}"
            );
        }
        for (why, t) in refused.iter().chain(check_only.iter()) {
            let r = client.check(t.clone(), vec![hash]).await;
            assert!(
                matches!(r, Err(RelayError::InvalidArgument)),
                "check {why}: {r:?}"
            );
        }
        for (why, t) in refused.iter().chain(register_only.iter()) {
            let r = client
                .register_key(t.clone(), 2959, BearerKind::Deposit, [0x11; 32], [2; 16])
                .await;
            assert!(
                matches!(r, Err(RelayError::InvalidArgument)),
                "register {why}: {r:?}"
            );
        }
        assert_eq!(
            relay.requests.load(Ordering::SeqCst),
            0,
            "no request reached the relay"
        );
        assert_eq!(connector.dials(), 0, "no connection was even opened");

        // Control: the same client with fitting tokens does reach the (answering) relay.
        let write_a = token(CapabilityKind::Write, NS_A);
        let receipt = client
            .store(write_a.clone(), blob.clone(), 86_400)
            .await
            .unwrap();
        assert_eq!(receipt.blob_hash, hash);
        assert_eq!(client.get(read_a.clone(), hash).await.unwrap().data, blob);
        assert_eq!(client.get(write_a.clone(), hash).await.unwrap().data, blob);
        assert_eq!(
            client.list(read_a.clone(), vec![], 16).await.unwrap().0,
            vec![hash]
        );
        assert_eq!(
            client.check(write_a.clone(), vec![hash]).await.unwrap(),
            vec![hash]
        );
        // The same operations with the credentials their kind allows, and one registration.
        assert_eq!(
            client
                .store(deposit_a.clone(), blob.clone(), 86_400)
                .await
                .unwrap()
                .blob_hash,
            hash
        );
        assert_eq!(
            client.get(read_key_a.clone(), hash).await.unwrap().data,
            blob
        );
        assert_eq!(client.get(fetch_a.clone(), hash).await.unwrap().data, blob);
        assert_eq!(
            client.list(fetch_a.clone(), vec![], 16).await.unwrap().0,
            vec![hash]
        );
        assert_eq!(
            client.check(deposit_a, vec![hash]).await.unwrap(),
            vec![hash]
        );
        let answer = client
            .register_key(write_a, 2959, BearerKind::Deposit, [0x11; 32], [2; 16])
            .await
            .unwrap();
        assert_eq!(answer.result, RegisterResult::WrongPeriod);
        assert_eq!(answer.valid_until_unix, 0);
        assert_eq!(relay.requests.load(Ordering::SeqCst), 11);
        assert!(connector.dials() >= 1);
    }

    /// Tokens that are no ACCESS token of the embedded schedule never leave the device (the
    /// schedule-bound cases, with valid tokens of the test schedule, are in `tests/redeem.rs`).
    #[tokio::test]
    async fn a_token_the_schedule_does_not_bind_to_this_relay_is_never_sent() {
        let schedule = crate::entitlement::embedded_schedule().unwrap();
        let (relay, addr) = counting_relay(vec![]).await;
        let connector = TcpConnector::new(addr);
        let mut client = NamespaceClient::with_connector(connector.clone(), relay_onion(), NS_A);
        let mut forged = [0u8; 354];
        forged[1] = 2;
        // A real ES key id with a forged authenticator, at a relay the ES does not list.
        let key_id = schedule
            .keys()
            .find(|k| k.kind == Kind::Access)
            .unwrap()
            .key_id;
        let mut real_key = forged;
        real_key[66..98].copy_from_slice(&key_id);
        let mut wrong_type = forged;
        wrong_type[1] = 3;
        for (why, t) in [
            ("unknown key", forged.to_vec()),
            ("unlisted relay", real_key.to_vec()),
            ("wrong type", wrong_type.to_vec()),
            ("short", forged[..353].to_vec()),
            ("long", [&forged[..], &[0]].concat()),
            ("empty", vec![]),
        ] {
            let r = client.redeem(&t, [1; 16]).await;
            assert!(
                matches!(r, Err(RelayError::InvalidArgument)),
                "{why}: {r:?}"
            );
        }
        assert_eq!(relay.requests.load(Ordering::SeqCst), 0);
        assert_eq!(connector.dials(), 0, "no connection was opened");
    }

    /// The raw redeem plumbing: the request reaches the relay unchanged and its answer comes back.
    #[tokio::test]
    async fn the_redeem_rpc_reaches_the_relay() {
        let (relay, addr) = counting_relay(vec![]).await;
        let mut client = RelayClient::with_connector(TcpConnector::new(addr));
        let answer = RedeemRpc::redeem_token(
            &mut client,
            RedeemTokenRequest {
                version: PROTOCOL_VERSION,
                token: vec![1; 354],
                namespace_id: NS_A.to_vec(),
                request_id: vec![2; 16],
            },
        )
        .await
        .unwrap();
        assert_eq!(answer.result, RedeemResult::Replayed as i32);
        assert_eq!(relay.requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn packed_outcomes_have_the_documented_layout() {
        let ok = RedeemOutcome {
            result: RedeemResult::Ok,
            relay_period_id: 2959,
            relay_minute: 29_812_345,
            expiry_unix: 1_790_000_000,
            capability: Some(vec![0x77; 98]),
        };
        let p = ok.pack();
        assert_eq!(p.len(), 25 + 98);
        assert_eq!(p[0], 1);
        assert_eq!(&p[1..9], &2959u64.to_be_bytes());
        assert_eq!(&p[9..17], &29_812_345u64.to_be_bytes());
        assert_eq!(&p[17..25], &1_790_000_000u64.to_be_bytes());
        assert_eq!(format!("{ok:?}"), "RedeemOutcome(Ok, ..)");
        let replayed = RedeemOutcome {
            result: RedeemResult::Replayed,
            expiry_unix: 0,
            capability: None,
            ..ok
        };
        assert_eq!(replayed.pack().len(), 25);
        assert_eq!(replayed.pack()[0], 2);
    }
}
