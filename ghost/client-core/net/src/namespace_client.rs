//! Relay client bound to one namespace by type (Phase 7, invariant T21: isolation scope equals
//! capability scope).
//!
//! `GetBlobRequest` and `CheckBlobsRequest` carry no namespace: the relay takes it from the
//! capability. A caller that isolated a call under namespace A but passed a capability for
//! namespace B would send B's reads over A's circuits, linking the two namespaces at the relay.
//! [`NamespaceClient`] closes that: it is built only by [`NamespaceClient::over_tor`], which fixes
//! the circuit isolation to [`IsolationScope::Namespace`] of its namespace, its methods take no
//! namespace, and before any I/O every call parses the capability header
//! ([`ghost_relay_api::capability_header`]) and requires
//! - the header's namespace to equal the bound namespace, and
//! - the kind to fit the operation: write for store; read or write for get, list and check (at
//!   the relay a write capability also grants read).
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
use ghost_relay_api::proto::{RedeemResult, RedeemTokenRequest, RedeemTokenResponse};
use ghost_relay_api::{
    capability_format, capability_header, CapabilityFormat, CapabilityKind, PROTOCOL_VERSION,
    REQUEST_ID_BYTES,
};
use std::fmt;
use std::future::Future;
use std::time::Duration;

/// What an operation needs from its capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// Store: a write capability.
    Write,
    /// Get, list, check: a read or a write capability.
    Read,
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
    /// Test constructor over another connector (loopback relays).
    #[cfg(test)]
    pub(crate) fn with_connector(connector: C, relay: OnionAddress, namespace: [u8; 32]) -> Self {
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

    /// The T21 guard: the capability must name this client's namespace and fit the operation.
    fn authorize(&self, capability: &[u8], access: Access) -> Result<(), RelayError> {
        let header = capability_header(capability).ok_or(RelayError::InvalidArgument)?;
        let kind_fits = match access {
            Access::Write => header.kind == CapabilityKind::Write,
            Access::Read => matches!(header.kind, CapabilityKind::Read | CapabilityKind::Write),
        };
        if header.namespace != self.namespace || !kind_fits {
            return Err(RelayError::InvalidArgument);
        }
        Ok(())
    }

    /// Stores an already-encrypted, bucket-sized blob in the bound namespace (write capability).
    pub async fn store(
        &mut self,
        capability: Vec<u8>,
        ciphertext: Vec<u8>,
        ttl_seconds: u32,
    ) -> Result<StoreReceipt, RelayError> {
        self.authorize(&capability, Access::Write)?;
        self.inner
            .store(self.namespace, capability, ciphertext, ttl_seconds)
            .await
    }

    /// Fetches a blob of the bound namespace with its relay expiry (read or write capability).
    pub async fn get(
        &mut self,
        capability: Vec<u8>,
        blob_hash: [u8; 32],
    ) -> Result<FetchedBlob, RelayError> {
        self.authorize(&capability, Access::Read)?;
        self.inner.get(blob_hash, capability).await
    }

    /// Lists one page of the bound namespace (read or write capability). The returned cursor is
    /// empty (listing complete) or 8 bytes.
    pub async fn list(
        &mut self,
        capability: Vec<u8>,
        cursor: Vec<u8>,
        limit: u32,
    ) -> Result<(Vec<[u8; 32]>, Vec<u8>), RelayError> {
        self.authorize(&capability, Access::Read)?;
        self.inner
            .list(self.namespace, capability, cursor, limit)
            .await
    }

    /// Returns which of `hashes` (distinct) the relay holds in the bound namespace (read or
    /// write capability); the answer is a subset of the request, each hash at most once.
    pub async fn check(
        &mut self,
        capability: Vec<u8>,
        hashes: Vec<[u8; 32]>,
    ) -> Result<Vec<[u8; 32]>, RelayError> {
        self.authorize(&capability, Access::Read)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loopback::TcpConnector;
    use ghost_relay_api::proto::relay_service_server::{RelayService, RelayServiceServer};
    use ghost_relay_api::proto::*;
    use ghost_relay_api::{CapabilityHeader, CAPABILITY_MAC_BYTES};
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
        assert!(client.authorize(&write, Access::Write).is_ok());
        assert!(
            client.authorize(&write, Access::Read).is_ok(),
            "write grants read"
        );
        assert!(client.authorize(&read, Access::Read).is_ok());
        assert!(
            matches!(
                client.authorize(&read, Access::Write),
                Err(RelayError::InvalidArgument)
            ),
            "read never grants write"
        );
        // A redeemed (v2) write capability for this namespace passes the same guard.
        let redeemed = token_v2(CapabilityKind::Write, NS_A);
        assert!(client.authorize(&redeemed, Access::Write).is_ok());
        assert!(client.authorize(&redeemed, Access::Read).is_ok());
        for (why, t) in refused_for_every_operation() {
            for access in [Access::Write, Access::Read] {
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

        let mut refused = refused_for_every_operation();
        // Store additionally refuses a read capability of the right namespace.
        let read_a = token(CapabilityKind::Read, NS_A);
        for (why, t) in refused
            .iter()
            .chain([("read for store", read_a.clone())].iter())
        {
            let r = client.store(t.clone(), blob.clone(), 86_400).await;
            assert!(
                matches!(r, Err(RelayError::InvalidArgument)),
                "store {why}: {r:?}"
            );
        }
        for (why, t) in refused.drain(..) {
            let r = client.get(t.clone(), hash).await;
            assert!(
                matches!(r, Err(RelayError::InvalidArgument)),
                "get {why}: {r:?}"
            );
            let r = client.list(t.clone(), vec![], 16).await;
            assert!(
                matches!(r, Err(RelayError::InvalidArgument)),
                "list {why}: {r:?}"
            );
            let r = client.check(t, vec![hash]).await;
            assert!(
                matches!(r, Err(RelayError::InvalidArgument)),
                "check {why}: {r:?}"
            );
        }
        assert_eq!(
            relay.requests.load(Ordering::SeqCst),
            0,
            "no request reached the relay"
        );
        assert_eq!(connector.dials(), 0, "no connection was even opened");

        // Control: the same client with fitting capabilities does reach the (answering) relay.
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
        assert_eq!(client.check(write_a, vec![hash]).await.unwrap(), vec![hash]);
        assert_eq!(relay.requests.load(Ordering::SeqCst), 5);
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
