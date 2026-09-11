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

use crate::categories as cat;
use crate::isolation::IsolationScope;
use crate::onion::OnionAddress;
use crate::relay_client::RelayClient;
use crate::transport::{TorTransport, TransportConfig};
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jint, jlong};
use jni::JNIEnv;
use std::collections::HashMap;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, Once, OnceLock};
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
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("ghost-net")
            .enable_all()
            .build()
            .map_err(|_| cat::RUNTIME)?;
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

/// Stores a bucket-sized ciphertext. Returns `blob_hash(32) || expiry_unix_seconds(8, BE)`.
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
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let addr = onion(env, &relay)?;
        let ns = fixed32(env, &namespace)?;
        let cap = bytes(env, &capability)?;
        let data = bytes(env, &ciphertext)?;
        let ttl = u32::try_from(ttl_seconds).map_err(|_| cat::INVALID_ARGUMENT)?;
        let h = lookup(id)?;
        let transport = h.transport()?;
        let receipt = h.run(async {
            RelayClient::over_tor(transport, &addr, &IsolationScope::Namespace(ns))
                .store(ns, cap, data, ttl)
                .await
                .map_err(|e| cat::for_relay(&e))
        })?;
        let mut out = receipt.blob_hash.to_vec();
        out.extend_from_slice(&receipt.expiry_unix_seconds.to_be_bytes());
        to_java(env, &out)
    })
}

/// Returns the hash-verified, bucket-sized ciphertext.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorRelayTransport_nativeGet(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
    relay: JString,
    namespace: JByteArray,
    capability: JByteArray,
    blob_hash: JByteArray,
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let addr = onion(env, &relay)?;
        let ns = fixed32(env, &namespace)?;
        let cap = bytes(env, &capability)?;
        let hash = fixed32(env, &blob_hash)?;
        let h = lookup(id)?;
        let transport = h.transport()?;
        let data = h.run(async {
            RelayClient::over_tor(transport, &addr, &IsolationScope::Namespace(ns))
                .get(hash, cap)
                .await
                .map_err(|e| cat::for_relay(&e))
        })?;
        to_java(env, &data)
    })
}

/// Returns `cursor_len(1) || cursor || hashes (32 bytes each)`; the cursor is 0 or 8 bytes.
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
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let addr = onion(env, &relay)?;
        let ns = fixed32(env, &namespace)?;
        let cap = bytes(env, &capability)?;
        let cur = bytes(env, &cursor)?;
        let limit = u32::try_from(limit).map_err(|_| cat::INVALID_ARGUMENT)?;
        let h = lookup(id)?;
        let transport = h.transport()?;
        let (hashes, next) = h.run(async {
            RelayClient::over_tor(transport, &addr, &IsolationScope::Namespace(ns))
                .list(ns, cap, cur, limit)
                .await
                .map_err(|e| cat::for_relay(&e))
        })?;
        let cursor_len = u8::try_from(next.len()).map_err(|_| cat::MALFORMED_RESPONSE)?;
        let mut buf = Vec::with_capacity(1 + next.len() + hashes.len() * 32);
        buf.push(cursor_len);
        buf.extend_from_slice(&next);
        for h in hashes {
            buf.extend_from_slice(&h);
        }
        to_java(env, &buf)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_handle() -> Arc<Handle> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
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
}
