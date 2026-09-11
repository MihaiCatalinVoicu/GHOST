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

use crate::isolation::IsolationScope;
use crate::onion::OnionAddress;
use crate::relay_client::{
    BoxError, FetchedBlob, Io, OnionConnector, RelayClient, RelayError, StoreReceipt, StreamType,
};
use crate::transport::TorTransport;
use ghost_relay_api::{capability_header, CapabilityKind};
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
}

impl NamespaceClient<OnionConnector> {
    /// Client for `relay` over Tor on the circuits of `IsolationScope::Namespace(namespace)`. No
    /// connection is opened until the first accepted call. This is the only public constructor.
    pub fn over_tor(transport: &TorTransport, relay: &OnionAddress, namespace: [u8; 32]) -> Self {
        NamespaceClient {
            inner: RelayClient::over_tor(transport, relay, &IsolationScope::Namespace(namespace)),
            namespace,
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
    pub(crate) fn with_connector(connector: C, namespace: [u8; 32]) -> Self {
        NamespaceClient {
            inner: RelayClient::with_connector(connector),
            namespace,
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
        vec![
            ("empty", Vec::new()),
            ("truncated", good[..good.len() - 1].to_vec()),
            ("longer", longer),
            ("version 2", version2),
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
        let mut client = NamespaceClient::with_connector(connector.clone(), NS_A);

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
}
