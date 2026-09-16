//! GHOST blind relay node (Phase 5). Implements `ghost.relay.v1.RelayService` over the storage,
//! capability, gossip and prune crates. Transport-level anonymity and relay authentication are
//! provided by the onion service and the deployment (ADR-01, infra/relay); this crate assumes the
//! peer is unknown and treats every request as untrusted input with bounded parsing.

mod bearer;
pub mod capture;
pub mod redeem;
pub mod register;

use bearer::{week_ceil, week_floor, Op};
use capture::{hex_or_none, Capture, Event};
use ghost_relay_api::proto::relay_service_server::RelayService;
use ghost_relay_api::proto::*;
use ghost_relay_api::{
    bearer_credential, is_bucket_size, time_bucket, ttl_bucket_seconds, BearerKind,
    DEFAULT_TTL_SECONDS, HASH_BYTES, MAX_BATCH, PROTOCOL_VERSION, REQUEST_ID_BYTES,
};
use ghost_relay_capability::{
    scope_hash, Allowance, CapError, Capability, DepositLedger, DepositRecord, Kind, QuotaLedger,
    RelayKey,
};
use ghost_relay_prune::{KeyRegistrations, NullifierPeriods, SweepReport};
use ghost_relay_storage::keys::KeyStore;
use ghost_relay_storage::nullifiers::NullifierStore;
use ghost_relay_storage::{BlobStore, StoreError};
pub use redeem::{EntitlementPolicy, NullifierMode, RedeemRate, StartError};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};

/// The relay's time source, in unix seconds. The gRPC service and the start-up checks read it; the
/// `*_at(request, now)` handlers take an explicit time instead.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub struct RelayConfig {
    pub gossip_enabled: bool,
    pub max_ttl_seconds: u32,
    /// Token redemption (Phase 8 design §10.5). `None`, the default, disables `RedeemToken`
    /// (`UNIMPLEMENTED`) and opens no nullifier store. It also gives the relay its slot, without
    /// which every bearer credential v3 is refused (Phase 9 design §21.2 point 3).
    pub entitlement: Option<EntitlementPolicy>,
    /// Time source of the gRPC service and of the start-up checks (default: the system clock).
    pub clock: Clock,
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            gossip_enabled: false,
            max_ttl_seconds: DEFAULT_TTL_SECONDS,
            entitlement: None,
            clock: Arc::new(now_unix),
        }
    }
}

pub struct Relay {
    store: BlobStore,
    keys: KeyStore,
    key: RelayKey,
    ledger: Mutex<QuotaLedger>,
    deposits: Mutex<DepositLedger>,
    redeem: Option<redeem::Redeem>,
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

/// What authorized a store, get, check or list.
enum Authorized {
    /// A relay-minted capability (v1 or v2), verified under the relay key.
    Capability(Capability),
    /// A bearer credential v3 of this kind, backed by live registrations: their allowances, in
    /// the order a deposit is charged to them.
    Bearer(BearerKind, Vec<Allowance>),
}

impl Relay {
    /// Opens the relay's data directory. With `config.entitlement` set, the start-up checks of
    /// design §10.5 run first, at `config.clock`'s time, and any failure is a refusal to start
    /// ([`StartError`]): the relay's onion must be listed for its slot in the current week, the
    /// nullifier store must open as the policy's [`NullifierMode`] says and under `key`, and the
    /// schedule must be append-only against the relay's memory of earlier schedules (rule 5).
    /// The key registration store `keys.redb` (Phase 9 design §4.6) is soft state: it is created
    /// empty when missing, whatever the nullifier mode, and only a file of another schema is a
    /// refusal to start.
    pub fn open(
        data_dir: &Path,
        key: RelayKey,
        mut config: RelayConfig,
        capture_path: Option<&Path>,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(data_dir)?;
        let redeem = match config.entitlement.take() {
            Some(policy) => Some(redeem::Redeem::open(
                policy,
                data_dir,
                &key,
                (config.clock)(),
            )?),
            None => None,
        };
        let store = BlobStore::open(&data_dir.join("blobs.redb"))?;
        let keys = KeyStore::open(&data_dir.join(register::KEYS_FILE))?;
        let capture = match capture_path {
            Some(p) => Some(Capture::open(p)?),
            None => None,
        };
        Ok(Arc::new(Relay {
            store,
            keys,
            key,
            ledger: Mutex::new(QuotaLedger::default()),
            deposits: Mutex::new(DepositLedger::default()),
            redeem,
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

    /// The key registration store (`keys.redb`).
    pub fn key_store(&self) -> &KeyStore {
        &self.keys
    }

    /// The relay's slot in the Entitlement Schedule, when redemption is enabled; bearer
    /// credentials v3 are accepted only for it.
    pub fn slot(&self) -> Option<u8> {
        self.redeem.as_ref().map(|r| r.slot())
    }

    /// The nullifier store, when redemption is enabled.
    pub fn nullifier_store(&self) -> Option<&NullifierStore> {
        self.redeem.as_ref().map(|r| r.store())
    }

    /// The in-memory quota ledger's state (read-only, [`QuotaLedger::snapshot`]): the T2 exit gate
    /// exports it with the relay's databases (design §13.4).
    pub fn quota_snapshot(&self) -> (Vec<([u8; 32], u64, u64)>, u64) {
        self.ledger.lock().unwrap().snapshot()
    }

    /// The in-memory deposit ledger's state (read-only, [`DepositLedger::snapshot`]): the T2 world
    /// exports it with `keys.redb` (Phase 9 design §4.9).
    pub fn deposit_ledger_snapshot(&self) -> (Vec<(DepositRecord, u64, u64)>, u64) {
        self.deposits.lock().unwrap().snapshot()
    }

    /// The relay's current time (its configured [`Clock`]).
    pub fn now(&self) -> u64 {
        (self.config.clock)()
    }

    /// Runbook R2 (design §6.9 check 2): writes the redemption counts file
    /// ([`redeem::redemption_counts_text`]: the final count of every closed week the nullifier
    /// store keeps, for this relay's slot) to `path` when its content changed. The binary calls it
    /// at start and after every sweep. Returns whether it wrote; an error without redemption.
    pub fn write_redemption_counts(&self, path: &Path) -> std::io::Result<bool> {
        let Some(r) = &self.redeem else {
            return Err(std::io::Error::other("redemption is disabled"));
        };
        let counts = r
            .store()
            .redemption_counts()
            .map_err(std::io::Error::other)?;
        redeem::write_if_changed(path, &redeem::redemption_counts_text(r.slot(), &counts))
    }

    /// One prune sweep at `now`: expired blobs and quota ledgers; key registrations past their
    /// validity and their deposit ledgers (Phase 9 design §4.5: nothing runs in `keys.redb` while
    /// `now` is below its persisted high-water minute); and, with redemption enabled, the nullifier
    /// rows of every access week whose acceptance window has closed (design §10.4: the
    /// closed-period high-water is raised in the same transaction, and nothing runs while `now` is
    /// below the persisted high-water minute). Called periodically by the binary and by tests.
    pub fn sweep(&self, now: u64) -> Result<SweepReport, StoreError> {
        let mut ledger = self.ledger.lock().unwrap();
        let mut deposits = self.deposits.lock().unwrap();
        let nullifiers = self.redeem.as_ref().map(|r| NullifierPeriods {
            store: r.store(),
            closed_through: redeem::closed_through(now),
        });
        let keys = KeyRegistrations {
            store: &self.keys,
            deposits: &mut deposits,
        };
        ghost_relay_prune::sweep(&self.store, &mut ledger, keys, nullifiers, now)
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

    /// Authorizes `token` for `op`: a bearer credential v3 through its registrations
    /// ([`Relay::accept_bearer`]), anything else as a relay-minted capability that grants write
    /// (store) or read (list) on `namespace`, or, for get and check, any right on its own
    /// namespace. Returns the namespace the operation may reveal. Every refusal is recorded as
    /// `rejected_capability`.
    fn authorize(
        &self,
        token: &[u8],
        op: Op,
        namespace: Option<&[u8; 32]>,
        now: u64,
        event: &mut Event,
    ) -> Result<([u8; 32], Authorized), Status> {
        let refused = |event: &mut Event, status: Status| {
            event.result = "rejected_capability";
            status
        };
        if let Some(credential) = bearer_credential(token) {
            return match self.accept_bearer(&credential, op, namespace, now) {
                Ok(accepted) => Ok((
                    credential.namespace,
                    Authorized::Bearer(credential.kind, accepted.allowances(&credential)),
                )),
                Err(refusal) => Err(refused(event, refusal.status())),
            };
        }
        let verified = match (op, namespace) {
            (Op::Store, Some(ns)) => self.key.verify(token, Kind::Write, ns, now),
            (Op::List, Some(ns)) => self.key.verify(token, Kind::Read, ns, now),
            _ => self.key.verify_any(token, now),
        };
        match verified {
            Ok(cap) => Ok((cap.namespace, Authorized::Capability(cap))),
            Err(e) => Err(refused(event, Relay::cap_error(e))),
        }
    }
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

/// Request handlers with an explicit clock. The gRPC service calls them with the wall clock;
/// conformance tests (`tests/semantics_vectors.rs`, `tests/register_vectors.rs`) call them with a
/// virtual one. Each records exactly one capture event, as the service did before the handlers
/// were extracted.
impl Relay {
    /// StoreBlob at time `now` (unix seconds). The TTL must be exactly one bucket (Phase 9 design
    /// §10.2, `rejected_ttl` otherwise). A store with a deposit credential is charged to the
    /// deposit ledger entry of its earliest live registration with allowance left (design §4.5).
    pub fn store_at(&self, req: StoreBlobRequest, now: u64) -> Result<StoreBlobResponse, Status> {
        let mut event = Event {
            op: "store",
            protocol_version: PROTOCOL_VERSION,
            namespace_id: hex_or_none(&req.namespace_id, HASH_BYTES),
            blob_hash: hex_or_none(&req.blob_hash, HASH_BYTES),
            size_bucket: is_bucket_size(req.data.len()).then_some(req.data.len()),
            time_bucket: time_bucket(now),
            ttl_bucket_seconds: ttl_bucket_seconds(req.ttl_seconds),
            capability_scope: req
                .capability
                .as_ref()
                .map(|c| hex::encode(scope_hash(&c.token))),
            request_id: hex_or_none(&req.request_id, REQUEST_ID_BYTES),
            result: "ok",
            ..Default::default()
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
            if ttl_bucket_seconds(req.ttl_seconds).is_none_or(|t| t > self.config.max_ttl_seconds) {
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
            let (_, authorized) =
                self.authorize(cap_token, Op::Store, Some(&namespace), now, &mut event)?;
            // The quota is charged inside the store's write transaction, before anything is
            // persisted: a store that exceeds the quota leaves no blob behind, and a retry is
            // charged again (it is not an "idempotent success").
            let bytes = req.data.len() as u64;
            let mut denied: Option<CapError> = None;
            let put = match authorized {
                Authorized::Capability(cap) => {
                    let mut ledger = self.ledger.lock().unwrap();
                    let mut charged = false;
                    let put = self.store.put(
                        &req.blob_hash,
                        &req.data,
                        &namespace,
                        u64::from(req.ttl_seconds),
                        now,
                        &mut || match ledger.charge(cap_token, &cap, bytes) {
                            Ok(()) => {
                                charged = true;
                                true
                            }
                            Err(e) => {
                                denied = Some(e);
                                false
                            }
                        },
                    );
                    if put.is_err() && charged {
                        ledger.refund(cap_token, bytes); // the write did not commit
                    }
                    put
                }
                Authorized::Bearer(_, allowances) => {
                    let mut deposits = self.deposits.lock().unwrap();
                    let mut charged: Option<DepositRecord> = None;
                    let put = self.store.put(
                        &req.blob_hash,
                        &req.data,
                        &namespace,
                        u64::from(req.ttl_seconds),
                        now,
                        &mut || match deposits.charge(&allowances, bytes) {
                            Ok(record) => {
                                charged = Some(record);
                                true
                            }
                            Err(e) => {
                                denied = Some(e);
                                false
                            }
                        },
                    );
                    if let (Err(_), Some(record)) = (&put, charged) {
                        deposits.refund(&record, bytes); // the write did not commit
                    }
                    put
                }
            };
            let outcome = match put {
                Ok(o) => o,
                Err(e) => {
                    return Err(match e {
                        StoreError::HashMismatch => {
                            event.result = "rejected_hash";
                            Status::invalid_argument(REJECTED)
                        }
                        StoreError::QuotaDenied => {
                            event.result = "rejected_capability";
                            Relay::cap_error(denied.unwrap_or(CapError::QuotaExceeded))
                        }
                        e => {
                            event.result = "rejected_size";
                            Relay::store_error(e)
                        }
                    });
                }
            };
            Ok(StoreBlobResponse {
                success: true,
                stored_hash: outcome.hash.to_vec(),
                expiry_unix_seconds: outcome.expiry,
            })
        })();

        self.record(event);
        outcome
    }

    /// GetBlob at time `now`. The namespace comes from the capability or credential. A read or
    /// fetch credential gets `uploaded_at` floored to the start of its ISO week, and a fetch
    /// credential also gets the expiry rounded up to the next ISO week boundary (Phase 9 design
    /// §21.9 point 4, §22.8.7 point 1); a relay-minted capability gets the upload minute and the
    /// hour-rounded expiry.
    pub fn get_at(&self, req: GetBlobRequest, now: u64) -> Result<GetBlobResponse, Status> {
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
            let (namespace, authorized) =
                self.authorize(cap_token, Op::Get, None, now, &mut event)?;
            event.namespace_id = Some(hex::encode(namespace));
            // Existence outside the capability's namespace is indistinguishable from absence.
            match self.store.get(&req.blob_hash, &namespace, now) {
                Ok(Some(b)) => {
                    event.size_bucket = Some(b.data.len());
                    let (uploaded, expiry) = match authorized {
                        Authorized::Capability(_) => (b.uploaded_minute, b.expiry_unix),
                        Authorized::Bearer(BearerKind::Fetch, _) => {
                            (week_floor(b.uploaded_minute), week_ceil(b.expiry_unix))
                        }
                        Authorized::Bearer(_, _) => (week_floor(b.uploaded_minute), b.expiry_unix),
                    };
                    Ok(GetBlobResponse {
                        data: b.data,
                        uploaded_at_unix_seconds: uploaded,
                        expiry_unix_seconds: expiry,
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
        outcome
    }

    /// CheckBlobs at time `now`. The namespace comes from the capability or credential.
    pub fn check_at(&self, req: CheckBlobsRequest, now: u64) -> Result<CheckBlobsResponse, Status> {
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
            let (namespace, _) = self.authorize(cap_token, Op::Check, None, now, &mut event)?;
            event.namespace_id = Some(hex::encode(namespace));
            match self.store.check(&req.blob_hashes, &namespace, now) {
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
        outcome
    }

    /// ListNamespace at time `now`.
    pub fn list_at(
        &self,
        req: ListNamespaceRequest,
        now: u64,
    ) -> Result<ListNamespaceResponse, Status> {
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
            self.authorize(cap_token, Op::List, Some(&namespace), now, &mut event)?;
            match self
                .store
                .list(&namespace, &req.cursor, req.limit as usize, now)
            {
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
        outcome
    }
}

#[tonic::async_trait]
impl RelayService for RelayServer {
    async fn store_blob(
        &self,
        request: Request<StoreBlobRequest>,
    ) -> Result<Response<StoreBlobResponse>, Status> {
        self.store_at(request.into_inner(), self.now())
            .map(Response::new)
    }

    async fn get_blob(
        &self,
        request: Request<GetBlobRequest>,
    ) -> Result<Response<GetBlobResponse>, Status> {
        self.get_at(request.into_inner(), self.now())
            .map(Response::new)
    }

    async fn check_blobs(
        &self,
        request: Request<CheckBlobsRequest>,
    ) -> Result<Response<CheckBlobsResponse>, Status> {
        self.check_at(request.into_inner(), self.now())
            .map(Response::new)
    }

    async fn list_namespace(
        &self,
        request: Request<ListNamespaceRequest>,
    ) -> Result<Response<ListNamespaceResponse>, Status> {
        self.list_at(request.into_inner(), self.now())
            .map(Response::new)
    }

    async fn redeem_token(
        &self,
        request: Request<RedeemTokenRequest>,
    ) -> Result<Response<RedeemTokenResponse>, Status> {
        self.redeem_at(request.into_inner(), self.now())
            .map(Response::new)
    }

    async fn register_key(
        &self,
        request: Request<RegisterKeyRequest>,
    ) -> Result<Response<RegisterKeyResponse>, Status> {
        self.register_key_at(request.into_inner(), self.now())
            .map(Response::new)
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
                let now = relay.now();
                let have = |h: &[u8]| matches!(relay.store.has_content(h), Ok(true));
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
