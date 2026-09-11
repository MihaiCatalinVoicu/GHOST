//! JNI surface for the Android `network` module (`org.ghost.network.TorRelayTransport`).
//!
//! Lifetime model: native state lives in a process-wide registry keyed by an opaque, never-reused
//! `jlong` id. Every call clones an `Arc` of its handle for the duration of the call, so
//! `nativeStop` can never free state under an in-flight call: it removes the id (a second stop is
//! a no-op) and signals cancellation; in-flight calls return `closed` promptly, and the runtime is
//! shut down when the last reference drops. No raw pointer ever crosses the boundary.
//!
//! Every entry point runs under `catch_unwind`, so a Rust panic becomes an `internal` exception
//! instead of aborting the process at the `extern "system"` boundary. A silent panic hook keeps
//! panic messages (which may carry detail) off stderr; a panic during unwinding or an allocation
//! failure still aborts. Only byte arrays, strings
//! and integers cross the boundary; errors surface as `org.ghost.network.NetworkException` with a
//! constant category (see [`crate::categories`]), never with relay or network detail.
//!
//! Relay calls (store, get, list, check) go through a [`NamespaceClient`] built per call for the
//! call's namespace, so the capability must name that namespace (T21), and each takes a
//! `deadlineMs`: the effective deadline is `min(deadlineMs, RELAY_RPC_DEADLINE)`; zero or a
//! negative value is `invalid_argument`. One handle serves concurrent calls from several JVM
//! threads: its runtime is multi-threaded and each call blocks only its own thread.

use crate::categories as cat;
use crate::namespace_client::NamespaceClient;
use crate::onion::OnionAddress;
use crate::relay_client::{FetchedBlob, OnionConnector, RelayError, RELAY_RPC_DEADLINE};
use crate::transport::{TorTransport, TransportConfig};
use ghost_relay_api::MAX_BATCH;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jint, jlong};
use jni::JNIEnv;
use std::collections::HashMap;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::watch;

const EXCEPTION: &str = "org/ghost/network/NetworkException";
const FALLBACK_EXCEPTION: &str = "java/lang/IllegalStateException";

type Outcome<T> = Result<T, &'static str>;

struct Handle {
    rt: Option<Runtime>,
    transport: Option<Arc<TorTransport>>,
    cancel: watch::Sender<bool>,
}

impl Handle {
    fn transport(&self) -> Outcome<&Arc<TorTransport>> {
        self.transport.as_ref().ok_or(cat::CLOSED)
    }

    /// Runs `fut` on this handle's runtime; returns `closed` as soon as the handle is stopped.
    fn run<T>(&self, fut: impl Future<Output = Outcome<T>>) -> Outcome<T> {
        let rt = self.rt.as_ref().ok_or(cat::CLOSED)?;
        let mut cancelled = self.cancel.subscribe();
        rt.block_on(async move {
            tokio::select! {
                biased;
                _ = cancelled.wait_for(|stopped| *stopped) => Err(cat::CLOSED),
                r = fut => r,
            }
        })
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // Runs when the last reference goes away (never inside the runtime: references are held
        // by JNI frames outside `block_on`). Drop Arti inside the runtime context, then stop it.
        let transport = self.transport.take();
        if let Some(rt) = self.rt.take() {
            {
                let _ctx = rt.enter();
                drop(transport);
            }
            rt.shutdown_background();
        }
    }
}

fn registry() -> &'static Mutex<HashMap<jlong, Arc<Handle>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<jlong, Arc<Handle>>>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

static NEXT_ID: AtomicI64 = AtomicI64::new(1);

/// Adds a handle to the registry under a fresh id (never 0, never reused).
fn register(handle: Arc<Handle>) -> jlong {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id, handle);
    id
}

/// Removes the handle and cancels its in-flight calls. The lock is released before cancelling;
/// the state itself is freed when the last in-flight call drops its reference. Idempotent.
fn stop(id: jlong) {
    let removed = registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id);
    if let Some(h) = removed {
        h.cancel.send_replace(true);
    }
}

fn lookup(id: jlong) -> Outcome<Arc<Handle>> {
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&id)
        .cloned()
        .ok_or(cat::CLOSED)
}

fn throw(env: &mut JNIEnv, category: &str) {
    // Never stack a second exception on a pending one (e.g. from a failed JNI conversion).
    if env.exception_check().unwrap_or(true) {
        return;
    }
    if env.throw_new(EXCEPTION, category).is_err() {
        // The class could not be found (e.g. renamed by R8): fall back to a platform class so the
        // caller still gets an exception with the category instead of a NoClassDefFoundError.
        let _ = env.exception_clear();
        let _ = env.throw_new(FALLBACK_EXCEPTION, category);
    }
}

fn quiet_panics() {
    static QUIET: Once = Once::new();
    QUIET.call_once(|| std::panic::set_hook(Box::new(|_| {})));
}

/// Runs a JNI body: panics become `internal`, errors become a `NetworkException(category)`.
fn guarded<'l, T>(
    env: &mut JNIEnv<'l>,
    default: T,
    body: impl FnOnce(&mut JNIEnv<'l>) -> Outcome<T>,
) -> T {
    quiet_panics();
    match catch_unwind(AssertUnwindSafe(|| body(env))) {
        Ok(Ok(v)) => v,
        Ok(Err(category)) => {
            throw(env, category);
            default
        }
        Err(_) => {
            throw(env, cat::INTERNAL);
            default
        }
    }
}

fn bytes(env: &JNIEnv, arr: &JByteArray) -> Outcome<Vec<u8>> {
    env.convert_byte_array(arr)
        .map_err(|_| cat::INVALID_ARGUMENT)
}

fn fixed32(env: &JNIEnv, arr: &JByteArray) -> Outcome<[u8; 32]> {
    bytes(env, arr)?
        .as_slice()
        .try_into()
        .map_err(|_| cat::INVALID_ARGUMENT)
}

fn string(env: &mut JNIEnv, s: &JString) -> Outcome<String> {
    env.get_string(s)
        .map(|j| j.into())
        .map_err(|_| cat::INVALID_ARGUMENT)
}

fn to_java(env: &mut JNIEnv, data: &[u8]) -> Outcome<jbyteArray> {
    env.byte_array_from_slice(data)
        .map(|a| a.into_raw())
        .map_err(|_| cat::INTERNAL)
}

fn onion(env: &mut JNIEnv, relay: &JString) -> Outcome<OnionAddress> {
    OnionAddress::parse(&string(env, relay)?).map_err(|_| cat::NOT_ONION)
}

/// The runtime of one handle: multi-threaded, so calls from several JVM threads (each blocking
/// in `Runtime::block_on`) proceed concurrently.
fn new_runtime() -> Outcome<Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("ghost-net")
        .enable_all()
        .build()
        .map_err(|_| cat::RUNTIME)
}

/// Per-call deadline from Kotlin: `min(deadline_ms, RELAY_RPC_DEADLINE)`; zero or negative is
/// `invalid_argument`.
fn deadline(deadline_ms: jint) -> Outcome<Duration> {
    match u64::try_from(deadline_ms) {
        Ok(ms) if ms > 0 => Ok(Duration::from_millis(ms).min(RELAY_RPC_DEADLINE)),
        _ => Err(cat::INVALID_ARGUMENT),
    }
}

/// Concatenated 32-byte hashes (the check request and response wire format), at most
/// `MAX_BATCH` of them.
fn hash_list(raw: &[u8]) -> Outcome<Vec<[u8; 32]>> {
    let (hashes, rest) = raw.as_chunks::<32>();
    if !rest.is_empty() || hashes.len() > MAX_BATCH {
        return Err(cat::INVALID_ARGUMENT);
    }
    Ok(hashes.to_vec())
}

/// `expiry_unix_seconds(8, BE) || data`: the get response wire format.
fn fetched_wire(blob: &FetchedBlob) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + blob.data.len());
    out.extend_from_slice(&blob.expiry_unix_seconds.to_be_bytes());
    out.extend_from_slice(&blob.data);
    out
}

/// `cursor_len(1) || cursor || hashes (32 bytes each)`: the list response wire format.
fn page_wire(hashes: &[[u8; 32]], next: &[u8]) -> Outcome<Vec<u8>> {
    let cursor_len = u8::try_from(next.len()).map_err(|_| cat::MALFORMED_RESPONSE)?;
    let mut buf = Vec::with_capacity(1 + next.len() + hashes.len() * 32);
    buf.push(cursor_len);
    buf.extend_from_slice(next);
    for h in hashes {
        buf.extend_from_slice(h);
    }
    Ok(buf)
}

/// A client for one call: bound to `namespace` (isolation and capability scope, T21), with the
/// call's deadline. Built inside the handle's runtime (the HTTP client needs a runtime context).
fn namespace_client(
    transport: &TorTransport,
    relay: &OnionAddress,
    namespace: [u8; 32],
    deadline: Duration,
) -> Outcome<NamespaceClient<OnionConnector>> {
    let mut client = NamespaceClient::over_tor(transport, relay, namespace);
    client
        .set_deadline(deadline)
        .map_err(|e| cat::for_relay(&e))?;
    Ok(client)
}

fn relay_category(e: RelayError) -> &'static str {
    cat::for_relay(&e)
}

/// Creates the Tor client without network access and returns an opaque id (never 0).
/// `bridgeLines` is newline-separated plain bridge lines; empty means direct Tor.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorRelayTransport_nativeCreate(
    mut env: JNIEnv,
    _class: JClass,
    state_dir: JString,
    cache_dir: JString,
    bridge_lines: JString,
) -> jlong {
    guarded(&mut env, 0, |env| {
        let cfg = TransportConfig {
            state_dir: PathBuf::from(string(env, &state_dir)?),
            cache_dir: PathBuf::from(string(env, &cache_dir)?),
            bridge_lines: string(env, &bridge_lines)?
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect(),
        };
        let rt = new_runtime()?;
        let transport = {
            let _ctx = rt.enter();
            TorTransport::create(&cfg).map_err(|e| cat::for_transport(&e))?
        };
        let (cancel, _) = watch::channel(false);
        let handle = Arc::new(Handle {
            rt: Some(rt),
            transport: Some(Arc::new(transport)),
            cancel,
        });
        Ok(register(handle))
    })
}

/// Bootstraps Tor, bounded by `BOOTSTRAP_DEADLINE`; `nativeStop` aborts it with `closed`.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorRelayTransport_nativeBootstrap(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
) {
    guarded(&mut env, (), |_env| {
        let h = lookup(id)?;
        let transport = h.transport()?;
        h.run(async {
            transport
                .bootstrap()
                .await
                .map_err(|e| cat::for_transport(&e))
        })
    })
}

/// Removes the handle and cancels in-flight calls. Idempotent; unknown ids are ignored.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorRelayTransport_nativeStop(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
) {
    guarded(&mut env, (), |_env| {
        stop(id);
        Ok(())
    })
}

#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorRelayTransport_nativeRotateCircuits(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
) {
    guarded(&mut env, (), |_env| {
        lookup(id)?.transport()?.rotate_circuits();
        Ok(())
    })
}

/// Stores a bucket-sized ciphertext with a write capability for `namespace`. Returns
/// `blob_hash(32) || expiry_unix_seconds(8, BE)`.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorRelayTransport_nativeStore(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
    relay: JString,
    namespace: JByteArray,
    capability: JByteArray,
    ciphertext: JByteArray,
    ttl_seconds: jint,
    deadline_ms: jint,
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let addr = onion(env, &relay)?;
        let ns = fixed32(env, &namespace)?;
        let cap = bytes(env, &capability)?;
        let data = bytes(env, &ciphertext)?;
        let ttl = u32::try_from(ttl_seconds).map_err(|_| cat::INVALID_ARGUMENT)?;
        let deadline = deadline(deadline_ms)?;
        let h = lookup(id)?;
        let transport = h.transport()?;
        let receipt = h.run(async {
            namespace_client(transport, &addr, ns, deadline)?
                .store(cap, data, ttl)
                .await
                .map_err(relay_category)
        })?;
        let mut out = receipt.blob_hash.to_vec();
        out.extend_from_slice(&receipt.expiry_unix_seconds.to_be_bytes());
        to_java(env, &out)
    })
}

/// Fetches a blob of `namespace` (read or write capability for it). Returns
/// `expiry_unix_seconds(8, BE) || data`: the relay's expiry, bounded natively, then the
/// hash-verified, bucket-sized ciphertext.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorRelayTransport_nativeGet(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
    relay: JString,
    namespace: JByteArray,
    capability: JByteArray,
    blob_hash: JByteArray,
    deadline_ms: jint,
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let addr = onion(env, &relay)?;
        let ns = fixed32(env, &namespace)?;
        let cap = bytes(env, &capability)?;
        let hash = fixed32(env, &blob_hash)?;
        let deadline = deadline(deadline_ms)?;
        let h = lookup(id)?;
        let transport = h.transport()?;
        let blob = h.run(async {
            namespace_client(transport, &addr, ns, deadline)?
                .get(cap, hash)
                .await
                .map_err(relay_category)
        })?;
        to_java(env, &fetched_wire(&blob))
    })
}

/// Lists a page of `namespace` (read or write capability for it). Returns
/// `cursor_len(1) || cursor || hashes (32 bytes each)`; the cursor is 0 or 8 bytes.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorRelayTransport_nativeList(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
    relay: JString,
    namespace: JByteArray,
    capability: JByteArray,
    cursor: JByteArray,
    limit: jint,
    deadline_ms: jint,
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let addr = onion(env, &relay)?;
        let ns = fixed32(env, &namespace)?;
        let cap = bytes(env, &capability)?;
        let cur = bytes(env, &cursor)?;
        let limit = u32::try_from(limit).map_err(|_| cat::INVALID_ARGUMENT)?;
        let deadline = deadline(deadline_ms)?;
        let h = lookup(id)?;
        let transport = h.transport()?;
        let (hashes, next) = h.run(async {
            namespace_client(transport, &addr, ns, deadline)?
                .list(cap, cur, limit)
                .await
                .map_err(relay_category)
        })?;
        to_java(env, &page_wire(&hashes, &next)?)
    })
}

/// Asks which of `hashes` (concatenated 32-byte hashes, at most 256) the relay holds in
/// `namespace` (read or write capability for it). Returns the held ones, concatenated; natively
/// checked to be a subset of the request.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorRelayTransport_nativeCheck(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
    relay: JString,
    namespace: JByteArray,
    capability: JByteArray,
    hashes: JByteArray,
    deadline_ms: jint,
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let addr = onion(env, &relay)?;
        let ns = fixed32(env, &namespace)?;
        let cap = bytes(env, &capability)?;
        let asked = hash_list(&bytes(env, &hashes)?)?;
        let deadline = deadline(deadline_ms)?;
        let h = lookup(id)?;
        let transport = h.transport()?;
        let held = h.run(async {
            namespace_client(transport, &addr, ns, deadline)?
                .check(cap, asked)
                .await
                .map_err(relay_category)
        })?;
        to_java(env, &held.concat())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A handle like `nativeCreate` builds (same runtime), without a Tor transport.
    fn test_handle() -> Arc<Handle> {
        let rt = new_runtime().unwrap();
        let (cancel, _) = watch::channel(false);
        Arc::new(Handle {
            rt: Some(rt),
            transport: None,
            cancel,
        })
    }

    #[test]
    fn stop_cancels_in_flight_calls_and_is_idempotent() {
        let h = test_handle();
        let id = register(Arc::clone(&h));
        let worker = {
            let h = lookup(id).unwrap();
            std::thread::spawn(move || {
                h.run(async {
                    tokio::time::sleep(std::time::Duration::from_secs(3_600)).await;
                    Ok::<_, &'static str>(())
                })
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(100));
        // The function nativeStop calls, twice.
        stop(id);
        stop(id);
        assert_eq!(worker.join().unwrap(), Err(cat::CLOSED));
        assert_eq!(lookup(id).err(), Some(cat::CLOSED));
        // Calls made after stop on a surviving reference also return `closed` immediately.
        assert_eq!(h.run(async { Ok::<_, &'static str>(1) }), Err(cat::CLOSED));
        drop(h); // last reference: runtime shuts down here, outside any async context
    }

    #[test]
    fn ids_are_never_zero_and_never_reused() {
        let a = register(test_handle());
        let b = register(test_handle());
        assert!(a > 0 && b > a);
        assert!(lookup(a).is_ok() && lookup(b).is_ok());
        stop(a);
        assert_eq!(lookup(a).err(), Some(cat::CLOSED));
        assert!(lookup(b).is_ok(), "stopping one id leaves the others alone");
        let c = register(test_handle());
        assert!(c > b, "a stopped id is never handed out again");
        stop(b);
        stop(c);
    }

    #[test]
    fn deadlines_are_capped_and_must_be_positive() {
        assert_eq!(deadline(0), Err(cat::INVALID_ARGUMENT));
        assert_eq!(deadline(-1), Err(cat::INVALID_ARGUMENT));
        assert_eq!(deadline(jint::MIN), Err(cat::INVALID_ARGUMENT));
        assert_eq!(deadline(1), Ok(Duration::from_millis(1)));
        assert_eq!(deadline(20_000), Ok(Duration::from_secs(20)));
        assert_eq!(deadline(60_000), Ok(RELAY_RPC_DEADLINE));
        assert_eq!(deadline(60_001), Ok(RELAY_RPC_DEADLINE));
        assert_eq!(deadline(jint::MAX), Ok(RELAY_RPC_DEADLINE));
    }

    #[test]
    fn wire_formats() {
        // check request/response: concatenated 32-byte hashes, at most MAX_BATCH.
        assert_eq!(hash_list(&[]), Ok(vec![]));
        let two: Vec<u8> = [[1u8; 32], [2u8; 32]].concat();
        assert_eq!(hash_list(&two), Ok(vec![[1u8; 32], [2u8; 32]]));
        assert_eq!(hash_list(&two[..63]), Err(cat::INVALID_ARGUMENT));
        assert_eq!(hash_list(&[0u8; 33]), Err(cat::INVALID_ARGUMENT));
        assert_eq!(
            hash_list(&vec![0u8; 32 * MAX_BATCH]).map(|v| v.len()),
            Ok(MAX_BATCH)
        );
        assert_eq!(
            hash_list(&vec![0u8; 32 * (MAX_BATCH + 1)]),
            Err(cat::INVALID_ARGUMENT)
        );
        // get: expiry(8, BE) || data.
        let wire = fetched_wire(&FetchedBlob {
            data: vec![9u8; 1024],
            expiry_unix_seconds: 0x0102_0304_0506_0708,
        });
        assert_eq!(wire.len(), 8 + 1024);
        assert_eq!(&wire[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(wire[8..].iter().all(|&b| b == 9));
        // list: cursor_len(1) || cursor || hashes.
        assert_eq!(page_wire(&[], &[]), Ok(vec![0]));
        let page = page_wire(&[[3u8; 32]], &[4u8; 8]).unwrap();
        assert_eq!(page.len(), 1 + 8 + 32);
        assert_eq!((page[0], page[1], page[9]), (8, 4, 3));
        assert_eq!(page_wire(&[], &[0u8; 256]), Err(cat::MALFORMED_RESPONSE));
    }

    /// Both lanes of the sync engine call into one handle from two JVM threads. Two calls block in
    /// `Runtime::block_on` on the same handle at once: each waits at a barrier that only opens
    /// when both are in flight, then stores through its own namespace client to a real relay.
    #[test]
    fn two_concurrent_calls_on_one_handle() {
        use crate::loopback::TcpConnector;
        use ghost_relay_api::proto::relay_service_server::RelayServiceServer;
        use ghost_relay_capability::{Capability, Kind, RelayKey};
        use ghost_relay_node::{Relay, RelayConfig, RelayServer};
        use sha2::Digest;
        use tokio_stream::wrappers::TcpListenerStream;

        let h = test_handle();
        let dir = tempfile::tempdir().unwrap();
        let relay = Relay::open(
            &dir.path().join("data"),
            RelayKey::generate(),
            RelayConfig::default(),
            None,
        )
        .unwrap();
        let rt = h.rt.as_ref().unwrap();
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let svc = RelayServiceServer::new(RelayServer(Arc::clone(&relay)));
        rt.spawn(async move {
            tonic::transport::Server::builder()
                .add_service(svc)
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
        });

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let calls: Vec<_> = [0x11u8, 0x22u8]
            .into_iter()
            .map(|seed| {
                let h = Arc::clone(&h);
                let barrier = Arc::clone(&barrier);
                let ns = [seed; 32];
                let cap = relay.key().mint(&Capability {
                    kind: Kind::Write,
                    namespace: ns,
                    quota_bytes: 1 << 20,
                    expiry_unix: u64::MAX,
                });
                std::thread::spawn(move || {
                    h.run(async move {
                        tokio::time::timeout(Duration::from_secs(20), barrier.wait())
                            .await
                            .map_err(|_| cat::TIMEOUT)?;
                        let mut client =
                            NamespaceClient::with_connector(TcpConnector::new(addr), ns);
                        client
                            .set_deadline(Duration::from_secs(20))
                            .map_err(relay_category)?;
                        client
                            .store(cap, vec![seed; 1024], 86_400)
                            .await
                            .map_err(relay_category)
                    })
                })
            })
            .collect();
        for (call, seed) in calls.into_iter().zip([0x11u8, 0x22u8]) {
            let receipt = call.join().unwrap().expect("both calls complete");
            let expected: [u8; 32] = sha2::Sha256::digest([seed; 1024]).into();
            assert_eq!(receipt.blob_hash, expected);
        }
        assert_eq!(relay.store().membership_count().unwrap(), 2);
        drop(h);
    }
}
