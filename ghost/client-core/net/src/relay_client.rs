//! gRPC relay client tunnelled through Tor. The tonic channel is built over a connector that only
//! knows how to open Arti streams to one onion address with one isolation token, so every request
//! on this client shares exactly that circuit set and nothing else.

use crate::isolation::IsolationScope;
use crate::onion::OnionAddress;
use crate::transport::{TorTransport, TransportError};
use arti_client::{DataStream, StreamPrefs, TorClient};
use ghost_relay_api::proto::relay_service_client::RelayServiceClient;
use ghost_relay_api::proto::*;
use ghost_relay_api::{PROTOCOL_VERSION, REQUEST_ID_BYTES};
use ghost_relay_transport::{pad, FrameError};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tonic::transport::{Channel, Endpoint};
use tor_rtcompat::PreferredRuntime;

#[derive(Debug)]
pub enum RelayError {
    Transport(TransportError),
    Rpc(tonic::Status),
    PayloadTooLarge,
    Malformed,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::Transport(e) => write!(f, "{e}"),
            RelayError::Rpc(s) => write!(f, "relay rejected request ({:?})", s.code()),
            RelayError::PayloadTooLarge => {
                f.write_str("payload exceeds the largest padding bucket")
            }
            RelayError::Malformed => f.write_str("relay returned a malformed response"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<tonic::Status> for RelayError {
    fn from(s: tonic::Status) -> Self {
        RelayError::Rpc(s)
    }
}

impl From<FrameError> for RelayError {
    fn from(_: FrameError) -> Self {
        RelayError::PayloadTooLarge
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// tower connector: ignores the URI (which is a fixed dummy) and dials the onion address.
#[derive(Clone)]
struct OnionConnector {
    client: Arc<TorClient<PreferredRuntime>>,
    addr: OnionAddress,
    isolation: arti_client::IsolationToken,
}

impl tower::Service<http::Uri> for OnionConnector {
    type Response = TokioIo<DataStream>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: http::Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let mut prefs = StreamPrefs::new();
            prefs.set_isolation(this.isolation);
            let stream = this
                .client
                .connect_with_prefs((this.addr.host(), this.addr.port()), &prefs)
                .await
                .map_err(|e| Box::new(TransportError::Connect(format!("{e}"))) as BoxError)?;
            Ok(TokioIo::new(stream))
        })
    }
}

pub struct RelayClient {
    inner: RelayServiceClient<Channel>,
}

fn request_id() -> Vec<u8> {
    rand::random::<[u8; REQUEST_ID_BYTES]>().to_vec()
}

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

impl RelayClient {
    /// Connects to `relay` through Tor using the circuit set of `scope`.
    pub async fn connect(
        transport: &TorTransport,
        relay: &OnionAddress,
        scope: &IsolationScope,
    ) -> Result<Self, RelayError> {
        let connector = OnionConnector {
            client: transport.client(),
            addr: relay.clone(),
            isolation: transport.isolations().token_for(scope),
        };
        // The URI is never resolved: the connector dials the onion address directly.
        let channel = Endpoint::from_static("http://onion.invalid")
            .connect_with_connector(connector)
            .await
            .map_err(|e| RelayError::Transport(TransportError::Connect(format!("{e}"))))?;
        Ok(RelayClient {
            inner: RelayServiceClient::new(channel),
        })
    }

    /// Pads `payload` to a bucket, hashes the padded blob and stores it. Returns the blob hash.
    pub async fn store(
        &mut self,
        namespace: [u8; 32],
        capability: Vec<u8>,
        payload: &[u8],
        ttl_seconds: u32,
    ) -> Result<[u8; 32], RelayError> {
        let blob = pad(payload)?;
        let hash = sha256(&blob);
        let resp = self
            .inner
            .store_blob(StoreBlobRequest {
                version: PROTOCOL_VERSION,
                blob_hash: hash.clone(),
                data: blob,
                capability: Some(Capability { token: capability }),
                ttl_seconds,
                request_id: request_id(),
                namespace_id: namespace.to_vec(),
            })
            .await?
            .into_inner();
        if !resp.success || resp.stored_hash != hash {
            return Err(RelayError::Malformed);
        }
        hash.try_into().map_err(|_| RelayError::Malformed)
    }

    /// Fetches a blob, verifies its hash and strips the padding. Returns the original payload.
    pub async fn get(
        &mut self,
        blob_hash: [u8; 32],
        capability: Vec<u8>,
    ) -> Result<Vec<u8>, RelayError> {
        let resp = self
            .inner
            .get_blob(GetBlobRequest {
                version: PROTOCOL_VERSION,
                blob_hash: blob_hash.to_vec(),
                capability: Some(Capability { token: capability }),
                request_id: request_id(),
            })
            .await?
            .into_inner();
        if sha256(&resp.data) != blob_hash {
            return Err(RelayError::Malformed);
        }
        let payload =
            ghost_relay_transport::unpad(&resp.data).map_err(|_| RelayError::Malformed)?;
        Ok(payload.to_vec())
    }

    pub async fn list(
        &mut self,
        namespace: [u8; 32],
        capability: Vec<u8>,
        cursor: Vec<u8>,
        limit: u32,
    ) -> Result<(Vec<[u8; 32]>, Vec<u8>), RelayError> {
        let resp = self
            .inner
            .list_namespace(ListNamespaceRequest {
                version: PROTOCOL_VERSION,
                namespace_id: namespace.to_vec(),
                capability: Some(Capability { token: capability }),
                cursor,
                limit,
            })
            .await?
            .into_inner();
        let mut hashes = Vec::with_capacity(resp.blob_hashes.len());
        for h in resp.blob_hashes {
            hashes.push(h.try_into().map_err(|_| RelayError::Malformed)?);
        }
        Ok((hashes, resp.next_cursor))
    }

    pub async fn check(
        &mut self,
        capability: Vec<u8>,
        hashes: Vec<[u8; 32]>,
    ) -> Result<Vec<[u8; 32]>, RelayError> {
        let resp = self
            .inner
            .check_blobs(CheckBlobsRequest {
                version: PROTOCOL_VERSION,
                blob_hashes: hashes.iter().map(|h| h.to_vec()).collect(),
                capability: Some(Capability { token: capability }),
            })
            .await?
            .into_inner();
        let mut out = Vec::new();
        for h in resp.available_hashes {
            out.push(h.try_into().map_err(|_| RelayError::Malformed)?);
        }
        Ok(out)
    }
}
