//! GHOST blind relay node (Phase 5). Implements `ghost.relay.v1.RelayService` over the storage,
//! capability, gossip and prune crates. Transport-level anonymity and relay authentication are
//! provided by the onion service and the deployment (ADR-01, infra/relay); this crate assumes the
//! peer is unknown and treats every request as untrusted input with bounded parsing.

pub mod capture;

use capture::{hex_or_none, Capture, Event};
use ghost_relay_api::proto::relay_service_server::RelayService;
use ghost_relay_api::proto::*;
use ghost_relay_api::{
    is_bucket_size, time_bucket, ttl_bucket_days, DEFAULT_TTL_SECONDS, HASH_BYTES, MAX_BATCH,
    PROTOCOL_VERSION, REQUEST_ID_BYTES,
};
use ghost_relay_capability::{
    scope_hash, CapError, Capability, Kind, NullifierSet, QuotaLedger, RelayKey,
};
use ghost_relay_storage::{BlobStore, StoreError};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};

pub struct RelayConfig {
    pub gossip_enabled: bool,
    pub max_ttl_seconds: u32,
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            gossip_enabled: false,
            max_ttl_seconds: DEFAULT_TTL_SECONDS,
        }
    }
}

pub struct Relay {
    store: BlobStore,
    key: RelayKey,
    ledger: Mutex<QuotaLedger>,
    nullifiers: Mutex<NullifierSet>,
    capture: Option<Capture>,
    config: RelayConfig,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// Error messages are constants: a relay never echoes client input back (§11.1).
const REJECTED: &str = "rejected";
const UNAUTHORIZED: &str = "unauthorized";
const NOT_FOUND: &str = "not found";

impl Relay {
    pub fn open(
        data_dir: &Path,
        key: RelayKey,
        config: RelayConfig,
        capture_path: Option<&Path>,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(data_dir)?;
        let store = BlobStore::open(&data_dir.join("blobs.redb"))?;
        let capture = match capture_path {
            Some(p) => Some(Capture::open(p)?),
            None => None,
        };
        Ok(Arc::new(Relay {
            store,
            key,
            ledger: Mutex::new(QuotaLedger::default()),
            nullifiers: Mutex::new(NullifierSet::default()),
            capture,
            config,
        }))
    }

    pub fn key(&self) -> &RelayKey {
        &self.key
    }

    pub fn store(&self) -> &BlobStore {
        &self.store
    }

    /// One prune sweep; called periodically by the binary and by tests.
    pub fn sweep(&self, now: u64) -> Result<ghost_relay_prune::SweepReport, StoreError> {
        let mut ledger = self.ledger.lock().unwrap();
        let mut nulls = self.nullifiers.lock().unwrap();
        let period = current_period(now);
        let prev = current_period(now.saturating_sub(86_400));
        ghost_relay_prune::sweep(&self.store, &mut ledger, &mut nulls, &[&period, &prev], now)
    }

    fn record(&self, event: Event) {
        if let Some(c) = &self.capture {
            c.record(&event);
        }
    }

    fn cap_error(e: CapError) -> Status {
        match e {
            CapError::QuotaExceeded => Status::resource_exhausted(REJECTED),
            _ => Status::permission_denied(UNAUTHORIZED),
        }
    }

    fn store_error(e: StoreError) -> Status {
        match e {
            StoreError::Db(_) => Status::unavailable(REJECTED),
            _ => Status::invalid_argument(REJECTED),
        }
    }
}

/// Nullifier validity periods are UTC days encoded as 8 big-endian bytes.
pub fn current_period(now: u64) -> [u8; 8] {
    (now / 86_400).to_be_bytes()
}

fn fixed<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.try_into().ok()
}

type GossipStream = Pin<Box<dyn Stream<Item = Result<GossipAck, Status>> + Send + 'static>>;

/// gRPC service handle over a shared [`Relay`].
#[derive(Clone)]
pub struct RelayServer(pub Arc<Relay>);

impl std::ops::Deref for RelayServer {
    type Target = Relay;
    fn deref(&self) -> &Relay {
        &self.0
    }
}

#[tonic::async_trait]
impl RelayService for RelayServer {
    async fn store_blob(
        &self,
        request: Request<StoreBlobRequest>,
    ) -> Result<Response<StoreBlobResponse>, Status> {
        let now = now_unix();
        let req = request.into_inner();
        let mut event = Event {
            op: "store",
            protocol_version: PROTOCOL_VERSION,
            namespace_id: hex_or_none(&req.namespace_id, HASH_BYTES),
            blob_hash: hex_or_none(&req.blob_hash, HASH_BYTES),
            size_bucket: is_bucket_size(req.data.len()).then_some(req.data.len()),
            time_bucket: time_bucket(now),
            ttl_bucket_days: ttl_bucket_days(req.ttl_seconds),
            capability_scope: req
                .capability
                .as_ref()
                .map(|c| hex::encode(scope_hash(&c.token))),
            request_id: hex_or_none(&req.request_id, REQUEST_ID_BYTES),
            batch_count: None,
            result: "ok",
        };

        let outcome: Result<StoreBlobResponse, Status> = (|| {
            if req.version != PROTOCOL_VERSION || req.request_id.len() != REQUEST_ID_BYTES {
                event.result = "rejected_size";
                return Err(Status::invalid_argument(REJECTED));
            }
            let Some(namespace) = fixed::<32>(&req.namespace_id) else {
                event.result = "rejected_size";
                return Err(Status::invalid_argument(REJECTED));
            };
            if req.ttl_seconds == 0 || req.ttl_seconds > self.config.max_ttl_seconds {
                event.result = "rejected_ttl";
                return Err(Status::invalid_argument(REJECTED));
            }
            if !is_bucket_size(req.data.len()) {
                event.result = "rejected_size";
                return Err(Status::invalid_argument(REJECTED));
            }
            let cap_token = req
                .capability
                .as_ref()
                .map(|c| c.token.as_slice())
                .unwrap_or(&[]);
            let cap: Capability = match self.key.verify(cap_token, Kind::Write, &namespace, now) {
                Ok(c) => c,
                Err(e) => {
                    event.result = "rejected_capability";
                    return Err(Relay::cap_error(e));
                }
            };
            let (hash, expiry, inserted) = match self.store.put(
                &req.blob_hash,
                &req.data,
                &namespace,
                req.ttl_seconds as u64,
                now,
            ) {
                Ok(r) => r,
                Err(StoreError::HashMismatch) => {
                    event.result = "rejected_hash";
                    return Err(Status::invalid_argument(REJECTED));
                }
                Err(e) => {
                    event.result = "rejected_size";
                    return Err(Relay::store_error(e));
                }
            };
            if inserted {
                let mut ledger = self.ledger.lock().unwrap();
                if let Err(e) = ledger.charge(cap_token, &cap, req.data.len() as u64) {
                    // Quota exceeded after insert would leave an orphan; charge first is
                    // equivalent here because put() is idempotent and the blob is content-addressed.
                    event.result = "rejected_capability";
                    return Err(Relay::cap_error(e));
                }
            }
            Ok(StoreBlobResponse {
                success: true,
                stored_hash: hash.to_vec(),
                expiry_unix_seconds: expiry,
            })
        })();

        self.record(event);
        outcome.map(Response::new)
    }

    async fn get_blob(
        &self,
        request: Request<GetBlobRequest>,
    ) -> Result<Response<GetBlobResponse>, Status> {
        let now = now_unix();
        let req = request.into_inner();
        let mut event = Event {
            op: "get",
            protocol_version: PROTOCOL_VERSION,
            blob_hash: hex_or_none(&req.blob_hash, HASH_BYTES),
            time_bucket: time_bucket(now),
            capability_scope: req
                .capability
                .as_ref()
                .map(|c| hex::encode(scope_hash(&c.token))),
            request_id: hex_or_none(&req.request_id, REQUEST_ID_BYTES),
            result: "ok",
            ..Default::default()
        };
        let outcome: Result<GetBlobResponse, Status> = (|| {
            if req.version != PROTOCOL_VERSION
                || req.request_id.len() != REQUEST_ID_BYTES
                || req.blob_hash.len() != HASH_BYTES
            {
                event.result = "rejected_size";
                return Err(Status::invalid_argument(REJECTED));
            }
            let cap_token = req
                .capability
                .as_ref()
                .map(|c| c.token.as_slice())
                .unwrap_or(&[]);
            let cap = match self.key.verify_any(cap_token, now) {
                Ok(c) => c,
                Err(e) => {
                    event.result = "rejected_capability";
                    return Err(Relay::cap_error(e));
                }
            };
            event.namespace_id = Some(hex::encode(cap.namespace));
            // Existence outside the capability's namespace is indistinguishable from absence.
            match self.store.get(&req.blob_hash, now) {
                Ok(Some(b)) if b.namespace == cap.namespace => {
                    event.size_bucket = Some(b.data.len());
                    Ok(GetBlobResponse {
                        data: b.data,
                        uploaded_at_unix_seconds: b.uploaded_minute,
                        expiry_unix_seconds: b.expiry_unix,
                    })
                }
                Ok(_) => {
                    event.result = "not_found";
                    Err(Status::not_found(NOT_FOUND))
                }
                Err(e) => {
                    event.result = "rejected_size";
                    Err(Relay::store_error(e))
                }
            }
        })();
        self.record(event);
        outcome.map(Response::new)
    }

    async fn check_blobs(
        &self,
        request: Request<CheckBlobsRequest>,
    ) -> Result<Response<CheckBlobsResponse>, Status> {
        let now = now_unix();
        let req = request.into_inner();
        let mut event = Event {
            op: "check",
            protocol_version: PROTOCOL_VERSION,
            time_bucket: time_bucket(now),
            capability_scope: req
                .capability
                .as_ref()
                .map(|c| hex::encode(scope_hash(&c.token))),
            batch_count: Some(req.blob_hashes.len() as u64),
            result: "ok",
            ..Default::default()
        };
        let outcome: Result<CheckBlobsResponse, Status> = (|| {
            if req.version != PROTOCOL_VERSION || req.blob_hashes.len() > MAX_BATCH {
                event.result = "rejected_size";
                return Err(Status::invalid_argument(REJECTED));
            }
            let cap_token = req
                .capability
                .as_ref()
                .map(|c| c.token.as_slice())
                .unwrap_or(&[]);
            let cap = match self.key.verify_any(cap_token, now) {
                Ok(c) => c,
                Err(e) => {
                    event.result = "rejected_capability";
                    return Err(Relay::cap_error(e));
                }
            };
            event.namespace_id = Some(hex::encode(cap.namespace));
            match self.store.check(&req.blob_hashes, &cap.namespace, now) {
                Ok(available) => Ok(CheckBlobsResponse {
                    available_hashes: available,
                }),
                Err(e) => {
                    event.result = "rejected_size";
                    Err(Relay::store_error(e))
                }
            }
        })();
        self.record(event);
        outcome.map(Response::new)
    }

    async fn list_namespace(
        &self,
        request: Request<ListNamespaceRequest>,
    ) -> Result<Response<ListNamespaceResponse>, Status> {
        let now = now_unix();
        let req = request.into_inner();
        let mut event = Event {
            op: "list",
            protocol_version: PROTOCOL_VERSION,
            namespace_id: hex_or_none(&req.namespace_id, HASH_BYTES),
            time_bucket: time_bucket(now),
            capability_scope: req
                .capability
                .as_ref()
                .map(|c| hex::encode(scope_hash(&c.token))),
            batch_count: Some(req.limit as u64),
            result: "ok",
            ..Default::default()
        };
        let outcome: Result<ListNamespaceResponse, Status> = (|| {
            let Some(namespace) = fixed::<32>(&req.namespace_id) else {
                event.result = "rejected_size";
                return Err(Status::invalid_argument(REJECTED));
            };
            if req.version != PROTOCOL_VERSION || req.limit == 0 || req.limit as usize > MAX_BATCH {
                event.result = "rejected_size";
                return Err(Status::invalid_argument(REJECTED));
            }
            let cap_token = req
                .capability
                .as_ref()
                .map(|c| c.token.as_slice())
                .unwrap_or(&[]);
            if let Err(e) = self.key.verify(cap_token, Kind::Read, &namespace, now) {
                event.result = "rejected_capability";
                return Err(Relay::cap_error(e));
            }
            match self.store.list(&namespace, &req.cursor, req.limit as usize) {
                Ok((hashes, next)) => Ok(ListNamespaceResponse {
                    blob_hashes: hashes.iter().map(|h| h.to_vec()).collect(),
                    next_cursor: next,
                }),
                Err(e) => {
                    event.result = "rejected_size";
                    Err(Relay::store_error(e))
                }
            }
        })();
        self.record(event);
        outcome.map(Response::new)
    }

    type GossipSyncStream = GossipStream;

    async fn gossip_sync(
        &self,
        request: Request<Streaming<GossipInventoryBatch>>,
    ) -> Result<Response<Self::GossipSyncStream>, Status> {
        if !self.config.gossip_enabled {
            return Err(Status::permission_denied(UNAUTHORIZED));
        }
        let relay = Arc::clone(&self.0);
        let mut inbound = request.into_inner();
        let output = async_stream(move |tx| async move {
            while let Some(item) = inbound.next().await {
                let batch = match item {
                    Ok(b) => b,
                    Err(_) => break,
                };
                let now = now_unix();
                let have = |h: &[u8]| matches!(relay.store.get(h, now), Ok(Some(_)));
                let result = ghost_relay_gossip::missing_from_batch(
                    &batch.blob_hashes,
                    &batch.batch_id,
                    have,
                );
                relay.record(Event {
                    op: "gossip",
                    protocol_version: PROTOCOL_VERSION,
                    time_bucket: time_bucket(now),
                    batch_count: Some(batch.blob_hashes.len() as u64),
                    result: if result.is_ok() {
                        "ok"
                    } else {
                        "rejected_size"
                    },
                    ..Default::default()
                });
                let msg = match result {
                    Ok(missing) => Ok(GossipAck {
                        batch_id: batch.batch_id,
                        missing_hashes: missing,
                    }),
                    Err(_) => Err(Status::invalid_argument(REJECTED)),
                };
                if tx.send(msg).await.is_err() {
                    break;
                }
            }
        });
        Ok(Response::new(output))
    }
}

/// Bridges an async producer to a boxed gRPC response stream.
fn async_stream<F, Fut>(producer: F) -> GossipStream
where
    F: FnOnce(tokio::sync::mpsc::Sender<Result<GossipAck, Status>>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(producer(tx));
    Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx))
}
