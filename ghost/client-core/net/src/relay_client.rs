//! gRPC relay client tunnelled through Tor.
//!
//! HTTP/2 runs over a hyper client whose only connector opens Arti streams to one onion address
//! with one isolation token, so every request on a client shares exactly that circuit set. tonic's
//! transport `Channel` is deliberately not used: it always adds a `user-agent: tonic/<version>`
//! header, which would let a relay partition clients by build (not an allowed observable).
//!
//! The client only moves opaque, already-encrypted, bucket-sized blobs. It never frames or pads
//! plaintext itself (padding belongs inside the AEAD plaintext, see `ghost-relay-transport`), it
//! snaps TTLs to the allowed buckets, bounds every RPC with a deadline of at most
//! [`RELAY_RPC_DEADLINE`], and treats every relay response as hostile input.
//!
//! A `RelayClient` is built only inside this crate: callers get one bound to a namespace through
//! [`crate::NamespaceClient::over_tor`], which also checks each capability against that namespace
//! before any I/O (T21).

use crate::isolation::IsolationScope;
use crate::onion::OnionAddress;
use crate::transport::{connect_isolated, TorTransport, TransportError};
use arti_client::{DataStream, TorClient};
use ghost_relay_api::proto::relay_service_client::RelayServiceClient;
use ghost_relay_api::proto::*;
use ghost_relay_api::{
    is_bucket_size, ttl_bucket_days, HASH_BYTES, MAX_BATCH, PROTOCOL_VERSION, REQUEST_ID_BYTES,
    TTL_BUCKETS_DAYS,
};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::{TokioExecutor, TokioIo};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite};
use tor_rtcompat::PreferredRuntime;

/// Upper bound for one relay RPC including the onion rendezvous and one 64 KiB transfer. A relay
/// that accepts a stream and never answers cannot pin the caller (AD-2 "may refuse or delay").
pub const RELAY_RPC_DEADLINE: Duration = Duration::from_secs(60);

/// Constant origin: never resolved (the connector ignores it), identical for every client.
const ORIGIN: &str = "http://relay.invalid";

#[derive(Debug)]
pub enum RelayError {
    Transport(TransportError),
    Rpc(tonic::Status),
    /// Blob length is not exactly a padding bucket (encrypt a padded frame first).
    NotBucketSized,
    /// Caller passed an out-of-range argument (TTL, batch size, cursor).
    InvalidArgument,
    /// The relay acknowledged a store that it would not serve (already-expired membership).
    NotStored,
    /// The relay returned data that violates the protocol (hash, size, expiry, cursor, batch
    /// bounds).
    Malformed,
    /// The call's deadline (at most [`RELAY_RPC_DEADLINE`]) elapsed.
    Timeout,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::Transport(e) => write!(f, "{e}"),
            RelayError::Rpc(s) => write!(f, "relay rejected request ({:?})", s.code()),
            RelayError::NotBucketSized => f.write_str("blob is not bucket-sized"),
            RelayError::InvalidArgument => f.write_str("invalid argument"),
            RelayError::NotStored => f.write_str("relay acknowledged a blob it will not serve"),
            RelayError::Malformed => f.write_str("relay returned a malformed response"),
            RelayError::Timeout => f.write_str("relay request timed out"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<tonic::Status> for RelayError {
    fn from(s: tonic::Status) -> Self {
        RelayError::Rpc(s)
    }
}

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A byte stream usable by hyper. Generic so tests can run the same client over loopback TCP.
pub struct Io<T> {
    inner: Pin<Box<TokioIo<T>>>,
}

impl<T> Io<T> {
    pub(crate) fn new(t: T) -> Self {
        Io {
            inner: Box::pin(TokioIo::new(t)),
        }
    }
}

impl<T: AsyncRead + AsyncWrite> hyper::rt::Read for Io<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.get_mut().inner.as_mut().poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite> hyper::rt::Write for Io<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.get_mut().inner.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut().inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut().inner.as_mut().poll_shutdown(cx)
    }
}

impl<T> Connection for Io<T> {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

/// Connector that ignores the request URI and dials one onion address on one isolation token.
#[derive(Clone)]
pub struct OnionConnector {
    client: Arc<TorClient<PreferredRuntime>>,
    addr: OnionAddress,
    isolation: arti_client::IsolationToken,
}

impl tower::Service<http::Uri> for OnionConnector {
    type Response = Io<DataStream>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: http::Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            // Same dial path as TorTransport::connect (covered by the live circuit test).
            let stream = connect_isolated(&this.client, &this.addr, this.isolation)
                .await
                .map_err(|e| Box::new(e) as BoxError)?;
            Ok(Io::new(stream))
        })
    }
}

/// Builds the connector for `scope`: the scope's isolation token, taken from the transport.
pub(crate) fn onion_connector(
    transport: &TorTransport,
    relay: &OnionAddress,
    scope: &IsolationScope,
) -> OnionConnector {
    OnionConnector {
        client: transport.client(),
        addr: relay.clone(),
        isolation: transport.isolation_token(scope),
    }
}

/// Result of a successful store: the blob hash and the expiry the relay holds for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreReceipt {
    pub blob_hash: [u8; 32],
    pub expiry_unix_seconds: u64,
}

/// Result of a successful get: the hash-verified, bucket-sized ciphertext and the expiry the
/// relay declares for it (at most now + 90 days + clock skew; a relay can still under-state it).
#[derive(Clone, PartialEq, Eq)]
pub struct FetchedBlob {
    pub data: Vec<u8>,
    pub expiry_unix_seconds: u64,
}

impl std::fmt::Debug for FetchedBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Ciphertext bytes stay out of debug output (test failures, panics).
        f.debug_struct("FetchedBlob")
            .field("len", &self.data.len())
            .field("expiry_unix_seconds", &self.expiry_unix_seconds)
            .finish()
    }
}

pub struct RelayClient<C> {
    inner: RelayServiceClient<HyperClient<C, tonic::body::Body>>,
    deadline: Duration,
}

fn request_id() -> Vec<u8> {
    rand::random::<[u8; REQUEST_ID_BYTES]>().to_vec()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn with_deadline<T>(
    deadline: Duration,
    fut: impl Future<Output = Result<tonic::Response<T>, tonic::Status>>,
) -> Result<T, RelayError> {
    match tokio::time::timeout(deadline, fut).await {
        Ok(Ok(resp)) => Ok(resp.into_inner()),
        Ok(Err(status)) => Err(transport_cause(&status)
            .map(RelayError::Transport)
            .unwrap_or(RelayError::Rpc(status))),
        Err(_) => Err(RelayError::Timeout),
    }
}

/// A connector failure (e.g. onion service unreachable) reaches us wrapped by hyper and tonic as
/// a `Status` with code `Unknown`; recover it so it is reported as a transport error, not as a
/// relay answer.
fn transport_cause(status: &tonic::Status) -> Option<TransportError> {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(status);
    while let Some(e) = cur {
        if let Some(t) = e.downcast_ref::<TransportError>() {
            return Some(t.clone());
        }
        cur = e.source();
    }
    None
}

/// Snaps a TTL to the smallest allowed bucket at or above it (threat model §6: relays observe
/// `ttl_bucket_days` only). Zero and anything above 90 days are rejected.
pub(crate) fn bucketed_ttl_seconds(ttl_seconds: u32) -> Result<u32, RelayError> {
    if ttl_seconds == 0 {
        return Err(RelayError::InvalidArgument);
    }
    let days = ttl_bucket_days(ttl_seconds).ok_or(RelayError::InvalidArgument)?;
    Ok(days * 86_400)
}

/// Clock difference tolerated between device and relay when checking a store receipt. Arti
/// itself accepts a device clock up to 3 days fast (directory post-valid tolerance).
pub(crate) const CLOCK_SKEW_SECONDS: u64 = 3 * 86_400;

/// Checks a store receipt. The relay must hold the blob for at least the requested (bucketed)
/// TTL, give or take [`CLOCK_SKEW_SECONDS`]: a receipt with a shorter expiry means the blob would
/// disappear early (e.g. another writer pre-stored the same ciphertext with a short TTL on a relay
/// that does not extend it) and is reported as `NotStored`. An expiry beyond the maximum TTL plus
/// skew is not a valid answer.
pub(crate) fn validate_store(
    hash: &[u8; 32],
    resp: &StoreBlobResponse,
    ttl_seconds: u32,
    now: u64,
) -> Result<StoreReceipt, RelayError> {
    if !resp.success || resp.stored_hash.as_slice() != hash {
        return Err(RelayError::Malformed);
    }
    let expiry = resp.expiry_unix_seconds;
    if expiry > latest_valid_expiry(now) {
        return Err(RelayError::Malformed);
    }
    if expiry.saturating_add(CLOCK_SKEW_SECONDS) < now.saturating_add(u64::from(ttl_seconds)) {
        return Err(RelayError::NotStored);
    }
    Ok(StoreReceipt {
        blob_hash: *hash,
        expiry_unix_seconds: resp.expiry_unix_seconds,
    })
}

/// Latest expiry a relay can truthfully declare at `now`: the maximum TTL bucket (90 days) plus
/// [`CLOCK_SKEW_SECONDS`].
fn latest_valid_expiry(now: u64) -> u64 {
    let max_ttl = u64::from(*TTL_BUCKETS_DAYS.last().expect("buckets")) * 86_400;
    now.saturating_add(max_ttl)
        .saturating_add(CLOCK_SKEW_SECONDS)
}

/// Checks a get response: bucket-sized data hashing to the requested blob, and an expiry no later
/// than [`latest_valid_expiry`] (a relay could otherwise make a recipient keep dedup state for an
/// arbitrary time). An early expiry cannot be detected here.
pub(crate) fn validate_get(
    hash: &[u8; 32],
    resp: GetBlobResponse,
    now: u64,
) -> Result<FetchedBlob, RelayError> {
    if !is_bucket_size(resp.data.len()) || sha256(&resp.data) != *hash {
        return Err(RelayError::Malformed);
    }
    if resp.expiry_unix_seconds > latest_valid_expiry(now) {
        return Err(RelayError::Malformed);
    }
    Ok(FetchedBlob {
        data: resp.data,
        expiry_unix_seconds: resp.expiry_unix_seconds,
    })
}

pub(crate) fn validate_list(
    resp: ListNamespaceResponse,
    limit: u32,
) -> Result<(Vec<[u8; 32]>, Vec<u8>), RelayError> {
    // Relay cursors are an opaque 8-byte sequence, or empty when the listing is complete.
    if !(resp.next_cursor.is_empty() || resp.next_cursor.len() == 8) {
        return Err(RelayError::Malformed);
    }
    if resp.blob_hashes.len() > limit as usize {
        return Err(RelayError::Malformed);
    }
    let mut hashes = Vec::with_capacity(resp.blob_hashes.len());
    for h in resp.blob_hashes {
        hashes.push(<[u8; 32]>::try_from(h.as_slice()).map_err(|_| RelayError::Malformed)?);
    }
    Ok((hashes, resp.next_cursor))
}

/// True when no hash occurs twice in `hashes`.
fn all_distinct(hashes: &[[u8; 32]]) -> bool {
    let mut seen = HashSet::with_capacity(hashes.len());
    hashes.iter().all(|h| seen.insert(h))
}

/// A check answer is a set drawn from the request (which never repeats a hash, see
/// [`RelayClient::check`]): whole 32-byte hashes, each one of the requested hashes, none twice,
/// hence no more than were requested. Anything else is `Malformed`; a relay answering `[a, a]`
/// to `[a, b]` cannot make one held hash count twice.
pub(crate) fn validate_check(
    requested: &[[u8; 32]],
    resp: CheckBlobsResponse,
) -> Result<Vec<[u8; 32]>, RelayError> {
    if resp.available_hashes.len() > requested.len() {
        return Err(RelayError::Malformed);
    }
    let mut out = Vec::with_capacity(resp.available_hashes.len());
    for h in resp.available_hashes {
        let h = <[u8; 32]>::try_from(h.as_slice()).map_err(|_| RelayError::Malformed)?;
        if !requested.contains(&h) || out.contains(&h) {
            return Err(RelayError::Malformed);
        }
        out.push(h);
    }
    Ok(out)
}

impl RelayClient<OnionConnector> {
    /// Client for `relay` over Tor on the circuit set of `scope`. No connection is opened until
    /// the first request; every request is bounded by [`RELAY_RPC_DEADLINE`]. Crate-private: the
    /// public way in is [`crate::NamespaceClient::over_tor`] (isolation scope = capability scope).
    pub(crate) fn over_tor(
        transport: &TorTransport,
        relay: &OnionAddress,
        scope: &IsolationScope,
    ) -> Self {
        Self::with_connector(onion_connector(transport, relay, scope))
    }
}

impl<C> RelayClient<C>
where
    C: tower::Service<http::Uri, Response = Io<C::Stream>> + Clone + Send + Sync + 'static,
    C: StreamType,
    C::Future: Unpin + Send,
    C::Error: Into<BoxError>,
{
    pub(crate) fn with_connector(connector: C) -> Self {
        let http = HyperClient::builder(TokioExecutor::new())
            .http2_only(true)
            .build(connector);
        let origin = http::Uri::from_static(ORIGIN);
        RelayClient {
            inner: RelayServiceClient::with_origin(http, origin),
            deadline: RELAY_RPC_DEADLINE,
        }
    }

    /// Sets the deadline of every later call to `min(deadline, RELAY_RPC_DEADLINE)`. A zero
    /// deadline is refused with [`RelayError::InvalidArgument`] (it could only fail every call).
    pub fn set_deadline(&mut self, deadline: Duration) -> Result<(), RelayError> {
        if deadline.is_zero() {
            return Err(RelayError::InvalidArgument);
        }
        self.deadline = deadline.min(RELAY_RPC_DEADLINE);
        Ok(())
    }

    /// Stores an already-encrypted, bucket-sized blob. The TTL is snapped to an allowed bucket.
    pub async fn store(
        &mut self,
        namespace: [u8; 32],
        capability: Vec<u8>,
        ciphertext: Vec<u8>,
        ttl_seconds: u32,
    ) -> Result<StoreReceipt, RelayError> {
        if !is_bucket_size(ciphertext.len()) {
            return Err(RelayError::NotBucketSized);
        }
        let ttl_seconds = bucketed_ttl_seconds(ttl_seconds)?;
        let hash = sha256(&ciphertext);
        let req = StoreBlobRequest {
            version: PROTOCOL_VERSION,
            blob_hash: hash.to_vec(),
            data: ciphertext,
            capability: Some(Capability { token: capability }),
            ttl_seconds,
            request_id: request_id(),
            namespace_id: namespace.to_vec(),
        };
        let resp = with_deadline(self.deadline, self.inner.store_blob(req)).await?;
        validate_store(&hash, &resp, ttl_seconds, now_unix())
    }

    /// Fetches a blob and verifies its size, hash and declared expiry. Returns the ciphertext
    /// unchanged, with the relay's expiry.
    pub async fn get(
        &mut self,
        blob_hash: [u8; 32],
        capability: Vec<u8>,
    ) -> Result<FetchedBlob, RelayError> {
        let req = GetBlobRequest {
            version: PROTOCOL_VERSION,
            blob_hash: blob_hash.to_vec(),
            capability: Some(Capability { token: capability }),
            request_id: request_id(),
        };
        let resp = with_deadline(self.deadline, self.inner.get_blob(req)).await?;
        validate_get(&blob_hash, resp, now_unix())
    }

    /// Lists a namespace page; the cursor returned is either empty (done) or 8 bytes.
    pub async fn list(
        &mut self,
        namespace: [u8; 32],
        capability: Vec<u8>,
        cursor: Vec<u8>,
        limit: u32,
    ) -> Result<(Vec<[u8; 32]>, Vec<u8>), RelayError> {
        if limit == 0 || limit as usize > MAX_BATCH || !(cursor.is_empty() || cursor.len() == 8) {
            return Err(RelayError::InvalidArgument);
        }
        let req = ListNamespaceRequest {
            version: PROTOCOL_VERSION,
            namespace_id: namespace.to_vec(),
            capability: Some(Capability { token: capability }),
            cursor,
            limit,
        };
        let resp = with_deadline(self.deadline, self.inner.list_namespace(req)).await?;
        validate_list(resp, limit)
    }

    /// Returns which of `hashes` the relay holds in the capability's namespace. The request
    /// names each hash at most once and at most `MAX_BATCH` of them (`InvalidArgument`
    /// otherwise, before any I/O); the answer holds each requested hash at most once.
    pub async fn check(
        &mut self,
        capability: Vec<u8>,
        hashes: Vec<[u8; 32]>,
    ) -> Result<Vec<[u8; 32]>, RelayError> {
        if hashes.len() > MAX_BATCH || !all_distinct(&hashes) {
            return Err(RelayError::InvalidArgument);
        }
        let req = CheckBlobsRequest {
            version: PROTOCOL_VERSION,
            blob_hashes: hashes.iter().map(|h| h.to_vec()).collect(),
            capability: Some(Capability { token: capability }),
        };
        let resp = with_deadline(self.deadline, self.inner.check_blobs(req)).await?;
        validate_check(&hashes, resp)
    }
}

/// Names the stream type a connector yields (lets `RelayClient` stay generic over TCP in tests).
pub trait StreamType {
    type Stream: AsyncRead + AsyncWrite + Send + 'static;
}

impl StreamType for OnionConnector {
    type Stream = DataStream;
}

// Compile-time guarantee that hash length constants agree with the array type used here.
const _: () = assert!(HASH_BYTES == 32);

#[cfg(test)]
#[allow(clippy::disallowed_methods, clippy::disallowed_types)] // loopback relays and TCP connectors
mod tests {
    use super::*;
    use crate::loopback::TcpConnector;
    use ghost_relay_api::proto::relay_service_server::RelayServiceServer;
    use ghost_relay_capability::{Capability as Cap, Kind, RelayKey};
    use ghost_relay_node::{Relay, RelayConfig, RelayServer};
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_stream::wrappers::TcpListenerStream;

    type Seen = Arc<Mutex<Vec<(bool, Option<String>)>>>;

    /// Starts a real relay node on loopback; records whether each request carried a user-agent.
    async fn relay() -> (Arc<Relay>, SocketAddr, Seen, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let relay = Relay::open(
            &dir.path().join("data"),
            RelayKey::generate(),
            RelayConfig::default(),
            None,
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let svc = RelayServiceServer::new(RelayServer(Arc::clone(&relay)));
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .layer(tower::util::MapRequestLayer::new(
                    move |req: http::Request<tonic::body::Body>| {
                        let ua = req
                            .headers()
                            .get(http::header::USER_AGENT)
                            .map(|v| v.to_str().unwrap_or("?").to_owned());
                        record.lock().unwrap().push((ua.is_some(), ua));
                        req
                    },
                ))
                .add_service(svc)
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        (relay, addr, seen, dir)
    }

    fn mint(relay: &Relay, kind: Kind, ns: [u8; 32]) -> Vec<u8> {
        relay.key().mint(&Cap {
            kind,
            namespace: ns,
            quota_bytes: 1 << 20,
            expiry_unix: now_unix() + 3_600,
        })
    }

    #[tokio::test]
    async fn round_trip_against_a_real_relay_without_user_agent() {
        let (relay, addr, seen, _dir) = relay().await;
        let mut client = RelayClient::with_connector(TcpConnector::new(addr));
        let ns = [0x42u8; 32];
        let write = mint(&relay, Kind::Write, ns);
        let read = mint(&relay, Kind::Read, ns);
        let blob: Vec<u8> = (0..4096u32).map(|i| (i * 7 % 251) as u8).collect();

        let receipt = client
            .store(ns, write.clone(), blob.clone(), 3 * 86_400)
            .await
            .unwrap();
        assert_eq!(receipt.blob_hash, sha256(&blob));
        // TTL was snapped to the 7-day bucket; the relay rounds expiries up to the hour.
        let expected = now_unix() + 7 * 86_400;
        assert!(
            receipt.expiry_unix_seconds + 5 >= expected
                && receipt.expiry_unix_seconds <= expected + 3_600 + 5
                && receipt.expiry_unix_seconds % 3_600 == 0,
            "expiry {}",
            receipt.expiry_unix_seconds
        );

        let fetched = client.get(receipt.blob_hash, read.clone()).await.unwrap();
        assert_eq!(fetched.data, blob);
        assert_eq!(
            fetched.expiry_unix_seconds, receipt.expiry_unix_seconds,
            "get returns the relay's expiry for the membership"
        );
        let (page, cursor) = client.list(ns, read.clone(), vec![], 16).await.unwrap();
        assert_eq!(page, vec![receipt.blob_hash]);
        assert!(cursor.is_empty());
        assert_eq!(
            client
                .check(read.clone(), vec![receipt.blob_hash, [9; 32]])
                .await
                .unwrap(),
            vec![receipt.blob_hash]
        );

        // Relay rejections surface as RPC errors with the relay's status code.
        match client.get([7; 32], read.clone()).await {
            Err(RelayError::Rpc(s)) => assert_eq!(s.code(), tonic::Code::NotFound),
            other => panic!("expected NotFound, got {other:?}"),
        }
        match client.store(ns, read, blob.clone(), 86_400).await {
            Err(RelayError::Rpc(s)) => assert_eq!(s.code(), tonic::Code::PermissionDenied),
            other => panic!("expected PermissionDenied, got {other:?}"),
        }

        let seen = seen.lock().unwrap();
        assert!(seen.len() >= 6);
        assert!(
            seen.iter().all(|(has_ua, _)| !has_ua),
            "requests must not carry a user-agent header: {seen:?}"
        );
    }

    #[tokio::test]
    async fn arguments_are_checked_before_any_request() {
        let connector = TcpConnector::new("127.0.0.1:9".parse().unwrap());
        let mut client = RelayClient::with_connector(connector.clone());
        assert!(matches!(
            client.set_deadline(Duration::ZERO),
            Err(RelayError::InvalidArgument)
        ));
        assert!(matches!(
            client.store([0; 32], vec![], vec![0u8; 1000], 86_400).await,
            Err(RelayError::NotBucketSized)
        ));
        assert!(matches!(
            client.store([0; 32], vec![], vec![0u8; 1024], 0).await,
            Err(RelayError::InvalidArgument)
        ));
        assert!(matches!(
            client
                .store([0; 32], vec![], vec![0u8; 1024], 91 * 86_400)
                .await,
            Err(RelayError::InvalidArgument)
        ));
        assert!(matches!(
            client.list([0; 32], vec![], vec![1, 2, 3], 10).await,
            Err(RelayError::InvalidArgument)
        ));
        assert!(matches!(
            client
                .list([0; 32], vec![], vec![], (MAX_BATCH + 1) as u32)
                .await,
            Err(RelayError::InvalidArgument)
        ));
        let distinct: Vec<[u8; 32]> = (0..=MAX_BATCH)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&(i as u64).to_be_bytes());
                h
            })
            .collect();
        assert!(matches!(
            client.check(vec![], distinct).await,
            Err(RelayError::InvalidArgument)
        ));
        // A hash named twice in one request (an honest relay would answer it twice).
        assert!(matches!(
            client.check(vec![], vec![[1; 32], [2; 32], [1; 32]]).await,
            Err(RelayError::InvalidArgument)
        ));
        assert_eq!(
            connector.dials(),
            0,
            "no argument error may open a connection"
        );
    }

    #[tokio::test]
    async fn the_deadline_is_capped_at_the_rpc_deadline() {
        let mut client =
            RelayClient::with_connector(TcpConnector::new("127.0.0.1:9".parse().unwrap()));
        assert_eq!(client.deadline, RELAY_RPC_DEADLINE);
        client.set_deadline(Duration::from_millis(1)).unwrap();
        assert_eq!(client.deadline, Duration::from_millis(1));
        client.set_deadline(Duration::from_secs(20)).unwrap();
        assert_eq!(client.deadline, Duration::from_secs(20));
        client.set_deadline(Duration::from_secs(61)).unwrap();
        assert_eq!(client.deadline, RELAY_RPC_DEADLINE);
        client.set_deadline(Duration::MAX).unwrap();
        assert_eq!(client.deadline, RELAY_RPC_DEADLINE);
        assert!(client.set_deadline(Duration::ZERO).is_err());
        assert_eq!(
            client.deadline, RELAY_RPC_DEADLINE,
            "a refused deadline changes nothing"
        );
    }

    #[tokio::test]
    async fn a_relay_that_never_answers_hits_the_deadline() {
        // Accepts the TCP connection and then says nothing.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        let mut client = RelayClient::with_connector(TcpConnector::new(addr));
        client.set_deadline(Duration::from_millis(300)).unwrap();
        let started = std::time::Instant::now();
        let r = client.get([1; 32], vec![]).await;
        assert!(matches!(r, Err(RelayError::Timeout)), "got {r:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn ttl_is_snapped_to_buckets() {
        assert_eq!(bucketed_ttl_seconds(1).unwrap(), 86_400);
        assert_eq!(bucketed_ttl_seconds(11_820).unwrap(), 86_400);
        assert_eq!(bucketed_ttl_seconds(2 * 86_400).unwrap(), 7 * 86_400);
        assert_eq!(bucketed_ttl_seconds(90 * 86_400).unwrap(), 90 * 86_400);
        assert!(bucketed_ttl_seconds(90 * 86_400 + 1).is_err());
        assert!(bucketed_ttl_seconds(0).is_err());
    }

    #[test]
    fn malicious_relay_responses_are_rejected() {
        let blob = vec![5u8; 1024];
        let h = sha256(&blob);
        // store: wrong hash, not success, expiry too short or impossibly long
        const DAY: u64 = 86_400;
        let now = 1_000_000;
        let receipt = |expiry| StoreBlobResponse {
            success: true,
            stored_hash: h.to_vec(),
            expiry_unix_seconds: expiry,
        };
        let ok = receipt(now + 30 * DAY);
        assert!(validate_store(&h, &ok, 30 * DAY as u32, now).is_ok());
        let wrong = StoreBlobResponse {
            stored_hash: vec![0; 32],
            ..ok.clone()
        };
        assert!(matches!(
            validate_store(&h, &wrong, 30 * DAY as u32, now),
            Err(RelayError::Malformed)
        ));
        let failed = StoreBlobResponse {
            success: false,
            ..ok.clone()
        };
        assert!(matches!(
            validate_store(&h, &failed, 30 * DAY as u32, now),
            Err(RelayError::Malformed)
        ));
        // A 30-day store answered with a 1-day expiry: the blob would vanish early.
        assert!(matches!(
            validate_store(&h, &receipt(now + DAY), 30 * DAY as u32, now),
            Err(RelayError::NotStored)
        ));
        assert!(matches!(
            validate_store(&h, &receipt(now - 4 * DAY), DAY as u32, now),
            Err(RelayError::NotStored)
        ));
        // A device clock up to 3 days fast still accepts a correct 1-day receipt.
        assert!(validate_store(&h, &receipt(now - 2 * DAY + 1), DAY as u32, now).is_ok());
        // A longer existing membership (relay keeps the max) is fine; beyond 90 days + skew is not.
        assert!(validate_store(&h, &receipt(now + 90 * DAY), DAY as u32, now).is_ok());
        assert!(matches!(
            validate_store(&h, &receipt(now + 94 * DAY), DAY as u32, now),
            Err(RelayError::Malformed)
        ));
        // get: tampered data, not bucket-sized
        let mut tampered = blob.clone();
        tampered[0] ^= 1;
        assert!(matches!(
            validate_get(
                &h,
                GetBlobResponse {
                    data: tampered,
                    ..Default::default()
                },
                now
            ),
            Err(RelayError::Malformed)
        ));
        let short = vec![5u8; 1000];
        assert!(matches!(
            validate_get(
                &sha256(&short),
                GetBlobResponse {
                    data: short,
                    ..Default::default()
                },
                now
            ),
            Err(RelayError::Malformed)
        ));
        // get: the declared expiry is bounded by now + 90 days + clock skew, inclusive.
        let served = |expiry| GetBlobResponse {
            data: blob.clone(),
            expiry_unix_seconds: expiry,
            ..Default::default()
        };
        let limit = now + 90 * DAY + CLOCK_SKEW_SECONDS;
        let fetched = validate_get(&h, served(limit), now).unwrap();
        assert_eq!(
            (fetched.data.as_slice(), fetched.expiry_unix_seconds),
            (&blob[..], limit)
        );
        assert!(matches!(
            validate_get(&h, served(limit + 1), now),
            Err(RelayError::Malformed)
        ));
        assert!(
            matches!(
                validate_get(&h, served(u64::MAX), u64::MAX - 10),
                Ok(FetchedBlob { .. })
            ),
            "saturating bound near the end of time"
        );
        // An early (even past) expiry is not detectable here and is passed on unchanged.
        assert_eq!(
            validate_get(&h, served(0), now)
                .unwrap()
                .expiry_unix_seconds,
            0
        );
        // list: oversized cursor (used to truncate through `as u8`), over-limit page, bad hash
        let long_cursor = ListNamespaceResponse {
            blob_hashes: vec![],
            next_cursor: vec![0; 256],
        };
        assert!(matches!(
            validate_list(long_cursor, 10),
            Err(RelayError::Malformed)
        ));
        let over = ListNamespaceResponse {
            blob_hashes: vec![vec![0; 32]; 3],
            next_cursor: vec![],
        };
        assert!(matches!(validate_list(over, 2), Err(RelayError::Malformed)));
        let bad_hash = ListNamespaceResponse {
            blob_hashes: vec![vec![0; 31]],
            next_cursor: vec![],
        };
        assert!(matches!(
            validate_list(bad_hash, 2),
            Err(RelayError::Malformed)
        ));
        // check: hashes the client never asked about
        let unasked = CheckBlobsResponse {
            available_hashes: vec![vec![8; 32]],
        };
        assert!(matches!(
            validate_check(&[[7; 32]], unasked),
            Err(RelayError::Malformed)
        ));
        let too_many = CheckBlobsResponse {
            available_hashes: vec![vec![7; 32]; 2],
        };
        assert!(matches!(
            validate_check(&[[7; 32]], too_many),
            Err(RelayError::Malformed)
        ));
        // check: a requested hash answered twice, within the request's count
        let repeated = CheckBlobsResponse {
            available_hashes: vec![vec![7; 32]; 2],
        };
        assert!(matches!(
            validate_check(&[[7; 32], [8; 32]], repeated),
            Err(RelayError::Malformed)
        ));
        // check: a subset in any order, each hash once, is accepted
        let subset = CheckBlobsResponse {
            available_hashes: vec![vec![9; 32], vec![7; 32]],
        };
        assert_eq!(
            validate_check(&[[7; 32], [8; 32], [9; 32]], subset).unwrap(),
            vec![[9; 32], [7; 32]]
        );
        assert!(all_distinct(&[]));
        assert!(all_distinct(&[[1; 32], [2; 32]]));
        assert!(!all_distinct(&[[1; 32], [2; 32], [1; 32]]));
    }

    /// A relay that answers every request with a protocol-violating response.
    struct HostileRelay;

    #[tonic::async_trait]
    impl ghost_relay_api::proto::relay_service_server::RelayService for HostileRelay {
        async fn store_blob(
            &self,
            r: tonic::Request<StoreBlobRequest>,
        ) -> Result<tonic::Response<StoreBlobResponse>, tonic::Status> {
            // Confirms the store, with an expiry that is already in the past.
            Ok(tonic::Response::new(StoreBlobResponse {
                success: true,
                stored_hash: r.into_inner().blob_hash,
                expiry_unix_seconds: 1,
            }))
        }
        async fn get_blob(
            &self,
            _r: tonic::Request<GetBlobRequest>,
        ) -> Result<tonic::Response<GetBlobResponse>, tonic::Status> {
            // Bucket-sized data that does not hash to the requested blob.
            Ok(tonic::Response::new(GetBlobResponse {
                data: vec![0xEE; 1024],
                ..Default::default()
            }))
        }
        async fn check_blobs(
            &self,
            _r: tonic::Request<CheckBlobsRequest>,
        ) -> Result<tonic::Response<CheckBlobsResponse>, tonic::Status> {
            Ok(tonic::Response::new(CheckBlobsResponse {
                available_hashes: vec![vec![0xAA; 32]], // never asked for
            }))
        }
        async fn list_namespace(
            &self,
            _r: tonic::Request<ListNamespaceRequest>,
        ) -> Result<tonic::Response<ListNamespaceResponse>, tonic::Status> {
            Ok(tonic::Response::new(ListNamespaceResponse {
                blob_hashes: vec![vec![1; 32]; 3], // more than the limit
                next_cursor: vec![],
            }))
        }
        type GossipSyncStream = tokio_stream::Empty<Result<GossipAck, tonic::Status>>;
        async fn gossip_sync(
            &self,
            _r: tonic::Request<tonic::Streaming<GossipInventoryBatch>>,
        ) -> Result<tonic::Response<Self::GossipSyncStream>, tonic::Status> {
            Err(tonic::Status::unimplemented("test"))
        }
        async fn redeem_token(
            &self,
            _r: tonic::Request<RedeemTokenRequest>,
        ) -> Result<tonic::Response<RedeemTokenResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("test"))
        }
    }

    #[tokio::test]
    async fn hostile_relay_answers_are_rejected_by_every_client_method() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(RelayServiceServer::new(HostileRelay))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let mut c = RelayClient::with_connector(TcpConnector::new(addr));
        let blob = vec![3u8; 1024];
        let r = c.store([1; 32], vec![], blob.clone(), 86_400).await;
        assert!(matches!(r, Err(RelayError::NotStored)), "store: {r:?}");
        let r = c.get(sha256(&blob), vec![]).await;
        assert!(matches!(r, Err(RelayError::Malformed)), "get: {r:?}");
        let r = c.list([1; 32], vec![], vec![], 2).await;
        assert!(matches!(r, Err(RelayError::Malformed)), "list: {r:?}");
        let r = c.check(vec![], vec![[7; 32]]).await;
        assert!(matches!(r, Err(RelayError::Malformed)), "check: {r:?}");
    }

    /// Connector standing in for an onion service that cannot be reached.
    #[derive(Clone)]
    struct UnreachableOnion;

    impl StreamType for UnreachableOnion {
        type Stream = TcpStream;
    }

    impl tower::Service<http::Uri> for UnreachableOnion {
        type Response = Io<TcpStream>;
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, _uri: http::Uri) -> Self::Future {
            Box::pin(async {
                Err(Box::new(TransportError::Connect("descriptor not found".into())) as BoxError)
            })
        }
    }

    #[tokio::test]
    async fn an_unreachable_relay_is_reported_as_transport() {
        let mut c = RelayClient::with_connector(UnreachableOnion);
        let err = c.get([1; 32], vec![]).await.unwrap_err();
        assert!(
            matches!(err, RelayError::Transport(TransportError::Connect(_))),
            "got {err:?}"
        );
        assert_eq!(
            crate::categories::for_relay(&err),
            crate::categories::TRANSPORT
        );
    }

    #[test]
    fn connector_carries_the_scope_isolation_token() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _g = rt.enter();
        let dir = tempfile::tempdir().unwrap();
        let t = TorTransport::create(&crate::TransportConfig {
            state_dir: dir.path().join("state"),
            cache_dir: dir.path().join("cache"),
            bridge_lines: vec![],
        })
        .unwrap();
        let relay = OnionAddress::parse(
            "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443",
        )
        .unwrap();
        let a = IsolationScope::Namespace([1; 32]);
        let b = IsolationScope::Namespace([2; 32]);
        let ca = onion_connector(&t, &relay, &a);
        let cb = onion_connector(&t, &relay, &b);
        assert_eq!(ca.isolation, t.isolation_token(&a));
        assert_eq!(cb.isolation, t.isolation_token(&b));
        assert_ne!(ca.isolation, cb.isolation);
    }
}
