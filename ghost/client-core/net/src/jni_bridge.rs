//! JNI surface for the Android `network` module (`org.ghost.network.TorRelayTransport`).
//!
//! Only byte arrays, strings and integers cross the boundary; errors surface as
//! `org.ghost.network.NetworkException` with a constant category string, never with relay or
//! network detail that could carry identifying data into logs.

use crate::isolation::IsolationScope;
use crate::onion::OnionAddress;
use crate::relay_client::{RelayClient, RelayError};
use crate::transport::{TorTransport, TransportConfig};
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jint, jlong};
use jni::JNIEnv;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::runtime::Runtime;

const EXCEPTION: &str = "org/ghost/network/NetworkException";

struct Handle {
    rt: Runtime,
    transport: Arc<TorTransport>,
}

fn throw(env: &mut JNIEnv, category: &str) {
    let _ = env.throw_new(EXCEPTION, category);
}

fn category(e: &RelayError) -> &'static str {
    match e {
        RelayError::Transport(_) => "transport",
        RelayError::Rpc(s) => match s.code() {
            tonic::Code::PermissionDenied => "unauthorized",
            tonic::Code::ResourceExhausted => "quota",
            tonic::Code::NotFound => "not_found",
            tonic::Code::InvalidArgument => "rejected",
            _ => "relay_unavailable",
        },
        RelayError::PayloadTooLarge => "payload_too_large",
        RelayError::Malformed => "malformed_response",
    }
}

fn bytes(env: &JNIEnv, arr: &JByteArray) -> Option<Vec<u8>> {
    env.convert_byte_array(arr).ok()
}

fn fixed32(v: &[u8]) -> Option<[u8; 32]> {
    v.try_into().ok()
}

fn string(env: &mut JNIEnv, s: &JString) -> Option<String> {
    env.get_string(s).ok().map(|j| j.into())
}

fn handle<'a>(ptr: jlong) -> &'a Handle {
    // SAFETY: `ptr` was produced by `nativeStart` via Box::into_raw and is only released by
    // `nativeStop`; the Kotlin wrapper guarantees no use after stop.
    unsafe { &*(ptr as *const Handle) }
}

/// Starts Tor and bootstraps. `bridgeLines` is newline-separated; empty means direct.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorRelayTransport_nativeStart(
    mut env: JNIEnv,
    _class: JClass,
    state_dir: JString,
    cache_dir: JString,
    bridge_lines: JString,
) -> jlong {
    let (Some(state), Some(cache), Some(bridges)) = (
        string(&mut env, &state_dir),
        string(&mut env, &cache_dir),
        string(&mut env, &bridge_lines),
    ) else {
        throw(&mut env, "invalid_argument");
        return 0;
    };
    let cfg = TransportConfig {
        state_dir: PathBuf::from(state),
        cache_dir: PathBuf::from(cache),
        bridge_lines: bridges
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect(),
    };
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(_) => {
            throw(&mut env, "runtime");
            return 0;
        }
    };
    match rt.block_on(TorTransport::bootstrap(&cfg)) {
        Ok(t) => Box::into_raw(Box::new(Handle {
            rt,
            transport: Arc::new(t),
        })) as jlong,
        Err(_) => {
            throw(&mut env, "tor_bootstrap");
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorRelayTransport_nativeStop(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) {
    if ptr != 0 {
        // SAFETY: see `handle`; ownership returns here exactly once.
        let h = unsafe { Box::from_raw(ptr as *mut Handle) };
        h.rt.shutdown_background();
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorRelayTransport_nativeRotateCircuits(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) {
    if ptr != 0 {
        handle(ptr).transport.isolations().rotate_all();
    }
}

fn with_client<T>(
    env: &mut JNIEnv,
    ptr: jlong,
    relay: &JString,
    namespace: [u8; 32],
    op: impl FnOnce(
        &mut RelayClient,
    )
        -> Pin<Box<dyn std::future::Future<Output = Result<T, RelayError>> + Send + '_>>,
) -> Option<T> {
    if ptr == 0 {
        throw(env, "not_started");
        return None;
    }
    let Some(addr) = string(env, relay).and_then(|s| OnionAddress::parse(&s).ok()) else {
        throw(env, "not_onion");
        return None;
    };
    let h = handle(ptr);
    let scope = IsolationScope::Namespace(namespace);
    let result = h.rt.block_on(async {
        let mut client = RelayClient::connect(&h.transport, &addr, &scope).await?;
        op(&mut client).await
    });
    match result {
        Ok(v) => Some(v),
        Err(e) => {
            throw(env, category(&e));
            None
        }
    }
}

use std::pin::Pin;

/// Returns the 32-byte blob hash.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorRelayTransport_nativeStore(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
    relay: JString,
    namespace: JByteArray,
    capability: JByteArray,
    payload: JByteArray,
    ttl_seconds: jint,
) -> jbyteArray {
    let (Some(ns), Some(cap), Some(data)) = (
        bytes(&env, &namespace).and_then(|v| fixed32(&v)),
        bytes(&env, &capability),
        bytes(&env, &payload),
    ) else {
        throw(&mut env, "invalid_argument");
        return std::ptr::null_mut();
    };
    if ttl_seconds <= 0 {
        throw(&mut env, "invalid_argument");
        return std::ptr::null_mut();
    }
    let hash = with_client(&mut env, ptr, &relay, ns, |c| {
        Box::pin(async move { c.store(ns, cap, &data, ttl_seconds as u32).await })
    });
    match hash {
        Some(h) => env
            .byte_array_from_slice(&h)
            .map(|a| a.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

/// Returns the unpadded payload.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorRelayTransport_nativeGet(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
    relay: JString,
    namespace: JByteArray,
    capability: JByteArray,
    blob_hash: JByteArray,
) -> jbyteArray {
    let (Some(ns), Some(cap), Some(hash)) = (
        bytes(&env, &namespace).and_then(|v| fixed32(&v)),
        bytes(&env, &capability),
        bytes(&env, &blob_hash).and_then(|v| fixed32(&v)),
    ) else {
        throw(&mut env, "invalid_argument");
        return std::ptr::null_mut();
    };
    let out = with_client(&mut env, ptr, &relay, ns, |c| {
        Box::pin(async move { c.get(hash, cap).await })
    });
    match out {
        Some(v) => env
            .byte_array_from_slice(&v)
            .map(|a| a.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

/// Returns `cursor_len(1) || cursor || hashes (32 bytes each)`.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorRelayTransport_nativeList(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
    relay: JString,
    namespace: JByteArray,
    capability: JByteArray,
    cursor: JByteArray,
    limit: jint,
) -> jbyteArray {
    let (Some(ns), Some(cap), Some(cur)) = (
        bytes(&env, &namespace).and_then(|v| fixed32(&v)),
        bytes(&env, &capability),
        bytes(&env, &cursor),
    ) else {
        throw(&mut env, "invalid_argument");
        return std::ptr::null_mut();
    };
    if limit <= 0 {
        throw(&mut env, "invalid_argument");
        return std::ptr::null_mut();
    }
    let out = with_client(&mut env, ptr, &relay, ns, |c| {
        Box::pin(async move { c.list(ns, cap, cur, limit as u32).await })
    });
    match out {
        Some((hashes, next)) => {
            let mut buf = Vec::with_capacity(1 + next.len() + hashes.len() * 32);
            buf.push(next.len() as u8);
            buf.extend_from_slice(&next);
            for h in hashes {
                buf.extend_from_slice(&h);
            }
            env.byte_array_from_slice(&buf)
                .map(|a| a.into_raw())
                .unwrap_or(std::ptr::null_mut())
        }
        None => std::ptr::null_mut(),
    }
}
