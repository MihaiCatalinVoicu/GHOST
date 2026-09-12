//! JNI surface for the Android `network` module: `org.ghost.network.TorRelayTransport`,
//! `org.ghost.network.TorIssuerTransport` and `org.ghost.network.EntitlementCrypto`.
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
//! failure still aborts. Only byte arrays, strings and integers cross the boundary; results are
//! fixed-layout byte strings (integers big-endian) that the Kotlin decoders read strictly; errors
//! surface as `org.ghost.network.NetworkException` with a constant category (see
//! [`crate::categories`]), never with relay, issuer or network detail.
//!
//! Relay calls (store, get, list, check, redeem) go through a [`NamespaceClient`] built per call
//! for the call's namespace, so the capability must name that namespace (T21), and each takes a
//! `deadlineMs`: the effective deadline is `min(deadlineMs, RELAY_RPC_DEADLINE)`; zero or a
//! negative value is `invalid_argument`. One handle serves concurrent calls from several JVM
//! threads: its runtime is multi-threaded and each call blocks only its own thread.
//!
//! Issuer calls (`TorIssuerTransport`, Phase 8 design §11.7) use the same handle, hence the same
//! Tor client, on the circuits of the call's issuer flow (`flow16`, 16 random bytes per flow
//! instance): an [`IssuerClient`] is built per call for the issuer onion of the embedded
//! Entitlement Schedule, and [`crate::issuer_flow`] checks the request before any I/O and the
//! answer against the ES. `nativeEndFlow` drops the flow's isolation token. `EntitlementCrypto` is
//! stateless: its functions read the embedded ES only ([`crate::entitlement`]). A schedule that
//! fails verification makes every entitlement call fail with `internal`.

use crate::categories as cat;
use crate::entitlement::{self, embedded_schedule, Product};
use crate::issuer_client::{IssuerClient, IssuerError};
use crate::issuer_flow;
use crate::namespace_client::NamespaceClient;
use crate::onion::OnionAddress;
use crate::relay_client::{FetchedBlob, OnionConnector, RelayError, RELAY_RPC_DEADLINE};
use crate::transport::{TorTransport, TransportConfig};
use ghost_entitlement::monero::AddressPurpose;
use ghost_entitlement::{Kind, Schedule, Token};
use ghost_relay_api::MAX_BATCH;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jint, jlong, jstring};
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

/// Ends an issuer flow on the transport of `id`: its isolation token is dropped. A stopped or
/// unknown id is a no-op (the transport's flow map went with it).
fn end_flow(id: jlong, flow: &[u8; 16]) {
    if let Ok(h) = lookup(id) {
        if let Ok(t) = h.transport() {
            t.end_issuer_flow(flow);
        }
    }
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

/// A byte array of exactly `N` bytes.
fn fixed<const N: usize>(env: &JNIEnv, arr: &JByteArray) -> Outcome<[u8; N]> {
    exact(&bytes(env, arr)?)
}

fn exact<const N: usize>(raw: &[u8]) -> Outcome<[u8; N]> {
    raw.try_into().map_err(|_| cat::INVALID_ARGUMENT)
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
    positive_millis(deadline_ms).map(|d| d.min(RELAY_RPC_DEADLINE))
}

/// A positive deadline in milliseconds; the issuer client caps it per call (60 s, or 120 s for
/// `BlindSign` and `RedeemInvite`).
fn positive_millis(ms: jint) -> Outcome<Duration> {
    match u64::try_from(ms) {
        Ok(ms) if ms > 0 => Ok(Duration::from_millis(ms)),
        _ => Err(cat::INVALID_ARGUMENT),
    }
}

/// A week, epoch or amount from Kotlin: never negative.
fn unsigned(v: jlong) -> Outcome<u64> {
    u64::try_from(v).map_err(|_| cat::INVALID_ARGUMENT)
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

fn issuer_category(e: IssuerError) -> &'static str {
    cat::for_issuer(&e)
}

/// The embedded Entitlement Schedule; a schedule that fails verification is `internal` (a broken
/// build, never a caller error).
fn schedule() -> Outcome<&'static Schedule> {
    embedded_schedule().map_err(|_| cat::INTERNAL)
}

/// One token of 354 bytes and type 0x0002.
fn one_token(raw: &[u8]) -> Outcome<Token> {
    Token::parse(raw).map_err(|_| cat::INVALID_ARGUMENT)
}

/// Concatenated 354-byte tokens.
fn token_list(raw: &[u8]) -> Outcome<Vec<Token>> {
    issuer_flow::parse_tokens(raw).map_err(issuer_category)
}

/// Runs one issuer call on the transport of `id`: a client for the embedded schedule's issuer
/// onion on the circuits of `flow`, with the caller's deadline.
fn with_issuer<T, F, Fut>(id: jlong, flow: [u8; 16], deadline: Duration, call: F) -> Outcome<T>
where
    F: FnOnce(IssuerClient<OnionConnector>, &'static Schedule) -> Fut,
    Fut: Future<Output = Result<T, IssuerError>>,
{
    let schedule = schedule()?;
    let h = lookup(id)?;
    let transport = h.transport()?;
    h.run(async move {
        let mut client =
            IssuerClient::over_tor(transport, schedule, flow).map_err(issuer_category)?;
        client.set_deadline(deadline).map_err(issuer_category)?;
        call(client, schedule).await.map_err(issuer_category)
    })
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
        let ns = fixed::<32>(env, &namespace)?;
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
        let ns = fixed::<32>(env, &namespace)?;
        let cap = bytes(env, &capability)?;
        let hash = fixed::<32>(env, &blob_hash)?;
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
        let ns = fixed::<32>(env, &namespace)?;
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

/// Asks which of `hashes` (concatenated distinct 32-byte hashes, at most 256; a repeated hash is
/// `invalid_argument`) the relay holds in `namespace` (read or write capability for it). Returns
/// the held ones, concatenated; natively checked to be a subset of the request, none twice.
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
        let ns = fixed::<32>(env, &namespace)?;
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

/// Redeems an entitlement token (354 bytes) for a write capability of `namespace` at `relay`
/// (design §10.9), with a 16-byte `requestId` identical on every retry. Before any I/O the token
/// must be bound by the embedded ES to this relay's slot in its week. Returns
/// `result(1) || relay_period(8) || relay_minute(8) || expiry(8) || capability(98 or 0)`, result
/// 1 OK (with the capability), 2 REPLAYED, 3 WRONG_PERIOD.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorRelayTransport_nativeRedeem(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
    relay: JString,
    namespace: JByteArray,
    token: JByteArray,
    request_id: JByteArray,
    deadline_ms: jint,
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let addr = onion(env, &relay)?;
        let ns = fixed::<32>(env, &namespace)?;
        let token = bytes(env, &token)?;
        let request_id = fixed::<16>(env, &request_id)?;
        let deadline = deadline(deadline_ms)?;
        let schedule = schedule()?;
        let h = lookup(id)?;
        let transport = h.transport()?;
        let outcome = h.run(async {
            namespace_client(transport, &addr, ns, deadline)?
                .redeem(schedule, &token, request_id)
                .await
                .map_err(relay_category)
        })?;
        to_java(env, &outcome.pack())
    })
}

/// `RequestInvoice` on flow `flow16` (16 bytes): `claimHash` (32), `credits` (0, or 10..20
/// concatenated CREDIT tokens covering the price), `baseWeek` (the device-clock week). Returns
/// `result(1) || invoice_id(16) || amount(8) || subaddress(0 or 95) || spent_mask(4)`, validated
/// against the ES (amount = ES price or 0, subaddress of the ES network).
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorIssuerTransport_nativeRequestInvoice(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
    flow: JByteArray,
    claim_hash: JByteArray,
    credits: JByteArray,
    base_week: jlong,
    deadline_ms: jint,
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let flow = fixed::<16>(env, &flow)?;
        let claim_hash = fixed::<32>(env, &claim_hash)?;
        let credits = token_list(&bytes(env, &credits)?)?;
        let base_week = unsigned(base_week)?;
        let deadline = positive_millis(deadline_ms)?;
        let answer = with_issuer(id, flow, deadline, |mut c, s| async move {
            issuer_flow::request_invoice(&mut c, s, &claim_hash, &credits, base_week).await
        })?;
        to_java(env, &answer.pack())
    })
}

/// `BlindSign` on flow `flow16`: `invoiceId` (16), `claimKey` (32), `seed` (32), `product` (1
/// pack-xmr, 2 pack-credits), `baseWeek` and the stored `layoutDigest` (32). Rust recomputes the
/// request from the seed. Returns `state(1) || credited(8) || seen(8)`, followed on SIGNED by
/// `N x (nullifier(32) || token(354))` in layout order.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorIssuerTransport_nativeBlindSign(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
    flow: JByteArray,
    invoice_id: JByteArray,
    claim_key: JByteArray,
    seed: JByteArray,
    product: jint,
    base_week: jlong,
    layout_digest: JByteArray,
    deadline_ms: jint,
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let flow = fixed::<16>(env, &flow)?;
        let invoice_id = fixed::<16>(env, &invoice_id)?;
        let claim_key = fixed::<32>(env, &claim_key)?;
        let seed = fixed::<32>(env, &seed)?;
        let product = Product::from_code(product).ok_or(cat::INVALID_ARGUMENT)?;
        let base_week = unsigned(base_week)?;
        let layout_digest = fixed::<32>(env, &layout_digest)?;
        let deadline = positive_millis(deadline_ms)?;
        let answer = with_issuer(id, flow, deadline, |mut c, s| async move {
            issuer_flow::blind_sign(
                &mut c,
                s,
                &invoice_id,
                &claim_key,
                &seed,
                product,
                base_week,
                &layout_digest,
            )
            .await
        })?;
        to_java(env, &answer.pack())
    })
}

/// `InvoiceStatus` on flow `flow16` (the optional "check now"). Returns
/// `state(1) || credited(8) || seen(8)`.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorIssuerTransport_nativeInvoiceStatus(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
    flow: JByteArray,
    invoice_id: JByteArray,
    claim_key: JByteArray,
    deadline_ms: jint,
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let flow = fixed::<16>(env, &flow)?;
        let invoice_id = fixed::<16>(env, &invoice_id)?;
        let claim_key = fixed::<32>(env, &claim_key)?;
        let deadline = positive_millis(deadline_ms)?;
        let answer = with_issuer(id, flow, deadline, |mut c, _s| async move {
            issuer_flow::invoice_status(&mut c, &invoice_id, &claim_key).await
        })?;
        to_java(env, &answer.pack())
    })
}

/// `RedeemInvite` on flow `flow16`: the invite token (354, verified offline first), `seed` (32),
/// `baseWeek` and the stored `layoutDigest`. Returns `result(1)` followed on OK by
/// `N_t x (nullifier(32) || token(354))`.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorIssuerTransport_nativeRedeemInvite(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
    flow: JByteArray,
    invite_token: JByteArray,
    seed: JByteArray,
    base_week: jlong,
    layout_digest: JByteArray,
    deadline_ms: jint,
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let flow = fixed::<16>(env, &flow)?;
        let invite = one_token(&bytes(env, &invite_token)?)?;
        let seed = fixed::<32>(env, &seed)?;
        let base_week = unsigned(base_week)?;
        let layout_digest = fixed::<32>(env, &layout_digest)?;
        let deadline = positive_millis(deadline_ms)?;
        let answer = with_issuer(id, flow, deadline, |mut c, s| async move {
            issuer_flow::redeem_invite(&mut c, s, &invite, &seed, base_week, &layout_digest).await
        })?;
        to_java(env, &answer.pack())
    })
}

/// `ClaimPayout` on flow `flow16`: `claimId` (16), the credits (concatenated CREDIT tokens,
/// `min_claim_credits .. max_claim_credits`) and the payout address (ES network). Returns
/// `result(1) || queued(8) || spent_mask(8)`.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorIssuerTransport_nativeClaimPayout(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
    flow: JByteArray,
    claim_id: JByteArray,
    credits: JByteArray,
    address: JString,
    deadline_ms: jint,
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let flow = fixed::<16>(env, &flow)?;
        let claim_id = fixed::<16>(env, &claim_id)?;
        let credits = token_list(&bytes(env, &credits)?)?;
        let address = string(env, &address)?;
        let deadline = positive_millis(deadline_ms)?;
        let answer = with_issuer(id, flow, deadline, |mut c, s| async move {
            issuer_flow::claim_payout(&mut c, s, &claim_id, &credits, &address).await
        })?;
        to_java(env, &answer.pack())
    })
}

/// `RefreshCredit` on flow `flow16` (design §19.8): the received credit (354), `seed` (32) and the
/// stored `layoutDigest` of `refresh(epoch of the credit)`. Returns `result(1)` followed on OK by
/// `nullifier(32) || token(354)` of the fresh credit.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorIssuerTransport_nativeRefreshCredit(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
    flow: JByteArray,
    received_credit: JByteArray,
    seed: JByteArray,
    layout_digest: JByteArray,
    deadline_ms: jint,
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let flow = fixed::<16>(env, &flow)?;
        let credit = one_token(&bytes(env, &received_credit)?)?;
        let seed = fixed::<32>(env, &seed)?;
        let layout_digest = fixed::<32>(env, &layout_digest)?;
        let deadline = positive_millis(deadline_ms)?;
        let answer = with_issuer(id, flow, deadline, |mut c, s| async move {
            issuer_flow::refresh_credit(&mut c, s, &credit, &seed, &layout_digest).await
        })?;
        to_java(env, &answer.pack())
    })
}

/// Drops the isolation token of flow `flow16` (16 bytes): later calls under that id get fresh
/// circuits. A stopped or unknown handle is a no-op.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorIssuerTransport_nativeEndFlow(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
    flow: JByteArray,
) {
    guarded(&mut env, (), |env| {
        let flow = fixed::<16>(env, &flow)?;
        end_flow(id, &flow);
        Ok(())
    })
}

/// The verified summary of the embedded ES ([`entitlement::schedule_summary`]).
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_EntitlementCrypto_nativeScheduleSummary(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let summary = entitlement::schedule_summary(schedule()?).map_err(|_| cat::INTERNAL)?;
        to_java(env, &summary)
    })
}

/// `digest(32) || N(4)` of `product` (1 pack-xmr, 2 pack-credits, 3 trial, 4 refresh) at `index`
/// (the base week; the credit epoch for a refresh). A layout the ES cannot build is
/// `invalid_argument`.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_EntitlementCrypto_nativeLayoutDigest(
    mut env: JNIEnv,
    _class: JClass,
    product: jint,
    index: jlong,
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let product = Product::from_code(product).ok_or(cat::INVALID_ARGUMENT)?;
        let index = unsigned(index)?;
        let layout = entitlement::layout_digest(schedule()?, product, index)
            .map_err(|_| cat::INVALID_ARGUMENT)?;
        to_java(env, &layout)
    })
}

/// Offline check of a token under the embedded ES for `kind` (1 access, any slot; 2 invite; 3
/// credit). Returns `kind(1) || epoch(8) || slot(1, 0xFF without) || nullifier(32)`; a refused
/// token is category `rejected`.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_EntitlementCrypto_nativeVerifyToken(
    mut env: JNIEnv,
    _class: JClass,
    token: JByteArray,
    kind: jint,
) -> jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let kind = u8::try_from(kind)
            .ok()
            .and_then(Kind::from_byte)
            .ok_or(cat::INVALID_ARGUMENT)?;
        let raw = bytes(env, &token)?;
        let verified = entitlement::verify_token(schedule()?, &raw, kind).ok_or(cat::REJECTED)?;
        to_java(env, &entitlement::pack_verified(&verified))
    })
}

/// Validates a Monero address of the ES network for `purpose` (1 invoice, 2 payout). Returns
/// `(network << 8) | type` (type 1 standard, 2 subaddress); a refused address is `rejected`.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_EntitlementCrypto_nativeValidateAddress(
    mut env: JNIEnv,
    _class: JClass,
    address: JString,
    purpose: jint,
) -> jint {
    guarded(&mut env, 0, |env| {
        let purpose = match purpose {
            1 => AddressPurpose::Invoice,
            2 => AddressPurpose::Payout,
            _ => return Err(cat::INVALID_ARGUMENT),
        };
        let address = string(env, &address)?;
        entitlement::validate_address(schedule()?, &address, purpose)
            .map(jint::from)
            .map_err(|_| cat::REJECTED)
    })
}

/// `monero:<subaddress>?tx_amount=<12 decimals>` for an ES-network subaddress and a positive
/// amount (a refused subaddress is `rejected`, an amount of 0 or less `invalid_argument`).
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_EntitlementCrypto_nativePaymentUri(
    mut env: JNIEnv,
    _class: JClass,
    subaddress: JString,
    amount_atomic: jlong,
) -> jstring {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let amount = unsigned(amount_atomic)
            .ok()
            .filter(|a| *a > 0)
            .ok_or(cat::INVALID_ARGUMENT)?;
        let subaddress = string(env, &subaddress)?;
        let uri = entitlement::payment_uri(schedule()?, &subaddress, amount)
            .map_err(|_| cat::REJECTED)?;
        env.new_string(uri)
            .map(|s| s.into_raw())
            .map_err(|_| cat::INTERNAL)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::IsolationScope;

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

    /// A handle exactly as `nativeCreate` builds it (a Tor client that has not bootstrapped).
    fn tor_handle(dir: &std::path::Path) -> Arc<Handle> {
        let rt = new_runtime().unwrap();
        let transport = {
            let _ctx = rt.enter();
            TorTransport::create(&TransportConfig {
                state_dir: dir.join("state"),
                cache_dir: dir.join("cache"),
                bridge_lines: vec![],
            })
            .unwrap()
        };
        let (cancel, _) = watch::channel(false);
        Arc::new(Handle {
            rt: Some(rt),
            transport: Some(Arc::new(transport)),
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

    /// The M4 target at the JNI boundary (design §19.17 point 6): two flows of one transport get
    /// distinct tokens, the function `nativeEndFlow` calls drops a flow's token, and a transport
    /// created after the first was stopped never hands out an earlier token.
    #[test]
    fn native_end_flow_drops_the_token_and_no_token_outlives_its_transport() {
        let dir = tempfile::tempdir().unwrap();
        let f1 = IsolationScope::IssuerFlow([0x51; 16]);
        let f2 = IsolationScope::IssuerFlow([0x52; 16]);
        let h = tor_handle(&dir.path().join("a"));
        let id = register(Arc::clone(&h));
        let token = |h: &Handle, s: &IsolationScope| h.transport().unwrap().isolation_token(s);
        let a1 = token(&h, &f1);
        let a2 = token(&h, &f2);
        assert_ne!(a1, a2);
        assert_eq!(token(&h, &f1), a1);
        end_flow(id, &[0x51; 16]);
        let b1 = token(&h, &f1);
        assert_ne!(b1, a1, "nativeEndFlow drops the flow's token");
        assert_eq!(token(&h, &f2), a2, "other flows keep theirs");
        stop(id);
        end_flow(id, &[0x52; 16]); // a stopped handle: no-op, no error
        drop(h);
        let h2 = tor_handle(&dir.path().join("b"));
        let id2 = register(Arc::clone(&h2));
        for s in [&f1, &f2] {
            assert!(![a1, a2, b1].contains(&token(&h2, s)), "reused after close");
        }
        stop(id2);
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
        // Issuer deadlines are only required positive here; the issuer client caps them.
        assert_eq!(positive_millis(0), Err(cat::INVALID_ARGUMENT));
        assert_eq!(positive_millis(-5), Err(cat::INVALID_ARGUMENT));
        assert_eq!(positive_millis(120_000), Ok(Duration::from_secs(120)));
    }

    #[test]
    fn integers_and_fixed_arrays_from_kotlin_are_strict() {
        assert_eq!(unsigned(0), Ok(0));
        assert_eq!(unsigned(2957), Ok(2957));
        assert_eq!(unsigned(-1), Err(cat::INVALID_ARGUMENT));
        assert_eq!(unsigned(jlong::MIN), Err(cat::INVALID_ARGUMENT));
        assert_eq!(exact::<16>(&[1; 16]), Ok([1; 16]));
        assert_eq!(exact::<16>(&[1; 15]), Err(cat::INVALID_ARGUMENT));
        assert_eq!(exact::<16>(&[1; 17]), Err(cat::INVALID_ARGUMENT));
        let mut t = [0u8; 354];
        t[1] = 2;
        assert!(one_token(&t).is_ok());
        assert_eq!(one_token(&t[..353]).err(), Some(cat::INVALID_ARGUMENT));
        assert_eq!(token_list(&[t, t].concat()).map(|v| v.len()), Ok(2));
        assert_eq!(token_list(&t[..100]).err(), Some(cat::INVALID_ARGUMENT));
        assert_eq!(schedule().map(|s| s.digest().len()), Ok(32));
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

        let onion = OnionAddress::parse(
            "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443",
        )
        .unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let calls: Vec<_> = [0x11u8, 0x22u8]
            .into_iter()
            .map(|seed| {
                let h = Arc::clone(&h);
                let barrier = Arc::clone(&barrier);
                let onion = onion.clone();
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
                            NamespaceClient::with_connector(TcpConnector::new(addr), onion, ns);
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
