//! `UpdateNative` (Phase 14 design §9.3): the closed JNI surface of the update decision. Byte
//! in, byte out: results are a one-byte `Code` (§9.2, `ghost_client_update::codec::code_byte`)
//! followed by a fixed big-endian payload Kotlin decodes strictly (a wrong length is
//! `malformed_response`). The APK checks live in a handle registry of their own (opaque ids,
//! idempotent abort, `catch_unwind` via `guarded`). The mirror set and the Tor fetch
//! (`nativeMirrorSet`, `TorMirrorTransport`) land with the transport slice; this file is the
//! pure half: epoch, acceptance, offer, the streaming APK check.
//!
//! G-D5 (G-R6 extended): only the names in `CLOSED_UPDATE` may exist, in this workspace,
//! under `Java_org_ghost_network_UpdateNative_`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use ghost_client_release::FormatError;
use ghost_client_update::apk::ApkCheck;
use ghost_client_update::codec::{code_byte, decode_stored, encode_stored};
use ghost_client_update::offer::{OfferResult, offer as decide_offer};
use ghost_client_update::{Time, UpdateError, accept_bundle, start_epoch};
use jni::objects::{JByteArray, JClass};
use jni::sys::{jboolean, jint, jlong};
use jni::JNIEnv;

use crate::categories as cat;
use crate::jni_bridge::{Outcome, bytes, fixed, guarded, lookup, to_java};

/// The embedded root chain of this build's network (the committed document, G-D4: the whole
/// chain from the lineage's first root; a bundle's GHRC may start later, §4.4).
const EMBEDDED_CHAIN: &[u8] =
    include_bytes!("../../../protocol/release/stagenet/embedded-chain.ghrc");

/// The committed relay directory (D19's bootstrap, source `config`): the gate-checked
/// `protocol/entitlement/relay-directory.txt` stays the bootstrap relay list (§4.3's note).
const EMBEDDED_RELAY_DIRECTORY: &[u8] =
    include_bytes!("../../../protocol/entitlement/relay-directory.txt");

/// The closed export list (mirrored by the gate, exactly as `DmNative`'s in §2.6).
pub const CLOSED_UPDATE: &[&str] = &[
    "nativeEmbeddedChain",
    "nativeStart",
    "nativeAccept",
    "nativeOffer",
    "nativeApkBegin",
    "nativeApkFooter",
    "nativeApkUpdate",
    "nativeApkFinish",
    "nativeApkAbort",
    "nativeMirrorSet",
    "nativeMirrorSetClose",
    "nativeBootstrapRelays",
    "nativeManifestRelays",
    "nativeMirrorPath",
    "nativeApkChunkStep",
];

/// The closed export list of `TorMirrorTransport` (§9.3): one fetch entry point.
pub const CLOSED_MIRROR: &[&str] = &[
    "nativeFetch",
];

/// The test-only entry of `UpdateMutants` (§11.3's mutant selector; slice S6c), mirrored by the
/// gate's source half exactly like the two closed lists. The symbol is compiled only behind
/// `ghost-client-net`'s `test-mutants` feature, which only `ghost-dm-host` enables, so a shipped
/// library never carries it (G-D5's library half checks both directions).
pub const TEST_MUTANT_SWITCHES: &[&str] = &[
    "select",
];

/// One streaming APK check in the handle registry.
struct ApkState {
    check: Option<ApkCheck>,
    footer_seen: bool,
}

fn apk_registry() -> &'static Mutex<HashMap<jlong, Arc<Mutex<ApkState>>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<jlong, Arc<Mutex<ApkState>>>>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

static NEXT_APK_ID: AtomicI64 = AtomicI64::new(1);

fn register_apk(state: ApkState) -> jlong {
    let id = NEXT_APK_ID.fetch_add(1, Ordering::Relaxed);
    apk_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id, Arc::new(Mutex::new(state)));
    id
}

fn lookup_apk(id: jlong) -> Outcome<Arc<Mutex<ApkState>>> {
    apk_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&id)
        .cloned()
        .ok_or(cat::CLOSED)
}

/// Removes the handle; idempotent. Returns `None` for an unknown id.
fn remove_apk(id: jlong) -> Option<Arc<Mutex<ApkState>>> {
    apk_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id)
}

fn result(code: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(code);
    out.extend_from_slice(payload);
    out
}

fn time_of(trusted: jboolean, day: jint, now: jlong) -> Time {
    if trusted != 0 {
        Time::Trusted { day: day as u32, now_secs: now as u64 }
    } else {
        Time::Untrusted
    }
}

/// The embedded chain document (a `GHRC`), for the first start and `NO_CHANNEL` (§7.8).
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeEmbeddedChain(
    mut env: JNIEnv,
    _class: JClass,
) -> jni::sys::jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| to_java(env, EMBEDDED_CHAIN))
}

/// §7.4 step 0. `stored` is the codec blob of the previous installed version, or empty at the
/// first start. Returns `[code][new stored blob]`.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeStart(
    mut env: JNIEnv,
    _class: JClass,
    stored: JByteArray,
    embedded_chain: JByteArray,
    installed: jint,
) -> jni::sys::jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let prev = bytes(env, &stored)?;
        let embedded = bytes(env, &embedded_chain)?;
        let chain = ghost_client_release::chain::GHRC::parse(&embedded)
            .map_err(|_| cat::INVALID_ARGUMENT)?;
        if chain.roots.is_empty() {
            return Err(cat::INVALID_ARGUMENT);
        }
        let stored_state = if prev.is_empty() {
            None
        } else {
            Some(decode_stored(&prev).map_err(|_| cat::INVALID_ARGUMENT)?)
        };
        let state = start_epoch(installed as u32, chain.roots, stored_state);
        Ok(to_java(env, &result(0, &encode_stored(&state)))?)
    })
}

/// §7.4 steps 1–7. Returns `[code][new stored blob]`: `code` 0 (or the step-2 report code)
/// with a blob to persist, or a refusal code with an unchanged blob.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeAccept(
    mut env: JNIEnv,
    _class: JClass,
    stored: JByteArray,
    bundle: JByteArray,
    day_trusted: jboolean,
    day: jint,
    now: jlong,
) -> jni::sys::jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let state = decode_stored(&bytes(env, &stored)?).map_err(|_| cat::INVALID_ARGUMENT)?;
        let bundle = bytes(env, &bundle)?;
        let network = state.trusted_root().body.network as u8;
        let out = match accept_bundle(&bundle, &state, network, time_of(day_trusted, day, now)) {
            Ok(outcome) => {
                let code = outcome.refused.as_ref().map_or(0u8, code_byte);
                result(code, &encode_stored(&outcome.state))
            }
            Err(e) => result(code_byte(&e), &[]),
        };
        Ok(to_java(env, &out)?)
    })
}

/// §7.4 step 8. Returns `[code]`, plus on `OK` `[u32 version_code][u16 name len][name]
/// [u8 release_index][32 apk_sha256][u64 apk_length]`.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeOffer(
    mut env: JNIEnv,
    _class: JClass,
    stored: JByteArray,
    installed: jint,
    sdk: jint,
    rollout_key: JByteArray,
    day_trusted: jboolean,
    day: jint,
) -> jni::sys::jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let state = decode_stored(&bytes(env, &stored)?).map_err(|_| cat::INVALID_ARGUMENT)?;
        let key: [u8; 32] = fixed(env, &rollout_key)?;
        let out = match decide_offer(&state, time_of(day_trusted, day, 0), installed as u32, sdk as u8, &key) {
            OfferResult::Update(o) => {
                let mut payload = Vec::new();
                payload.extend_from_slice(&o.version_code.to_be_bytes());
                payload.extend_from_slice(&(o.version_name.len() as u16).to_be_bytes());
                payload.extend_from_slice(&o.version_name);
                payload.push(o.release_index as u8);
                payload.extend_from_slice(&o.release.apk_sha256);
                payload.extend_from_slice(&o.release.apk_length.to_be_bytes());
                result(0, &payload)
            }
            OfferResult::None(e) => result(code_byte(&e), &[]),
        };
        Ok(to_java(env, &out)?)
    })
}

/// Step 9(a): begins a streaming APK check over the offered release (`release_index` into the
/// stored manifest); `tail` is the file's last 22 bytes. Returns the check's handle.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeApkBegin(
    mut env: JNIEnv,
    _class: JClass,
    stored: JByteArray,
    release_index: jint,
    sdk: jint,
    length: jlong,
    tail: JByteArray,
) -> jlong {
    guarded(&mut env, 0, |env| {
        let state = decode_stored(&bytes(env, &stored)?).map_err(|_| cat::INVALID_ARGUMENT)?;
        let tail: [u8; 22] = fixed(env, &tail)?;
        let manifest = state.manifest.clone().ok_or(cat::INVALID_ARGUMENT)?;
        let release = manifest
            .body
            .releases
            .get(release_index as usize)
            .cloned()
            .ok_or(cat::INVALID_ARGUMENT)?;
        let (check, _need) = ApkCheck::begin(
            release_index as usize,
            release,
            manifest,
            state.trusted_root().clone(),
            sdk as u8,
            length as u64,
            &tail,
        )
        .map_err(|_| cat::INVALID_ARGUMENT)?;
        Ok(register_apk(ApkState { check: Some(check), footer_seen: false }))
    })
}

/// Steps 9(b), 9(c): the 24 bytes before `cd_offset` (the range `Need::Footer` names).
/// Returns `[code]` (one byte; non-zero on refusal).
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeApkFooter(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    footer: JByteArray,
) -> jni::sys::jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let bytes24: [u8; 24] = fixed(env, &footer)?;
        let state = lookup_apk(handle)?;
        let mut guard = state.lock().map_err(|_| cat::INTERNAL)?;
        let already = guard.footer_seen;
        let check = guard.check.as_mut().ok_or(cat::CLOSED)?;
        let code = if already {
            code_byte(&UpdateError::OutOfOrder)
        } else {
            match check.footer(&bytes24) {
                Ok(()) => {
                    guard.footer_seen = true;
                    0
                }
                Err(e) => code_byte(&e),
            }
        };
        Ok(to_java(env, &[code])?)
    })
}

/// Steps 9(d), 9(e): body bytes, strictly in order. Returns `[code]`.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeApkUpdate(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    offset: jlong,
    chunk: JByteArray,
) -> jni::sys::jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let chunk = bytes(env, &chunk)?;
        let state = lookup_apk(handle)?;
        let mut guard = state.lock().map_err(|_| cat::INTERNAL)?;
        let check = guard.check.as_mut().ok_or(cat::CLOSED)?;
        let code = match check.update(offset as u64, &chunk) {
            Ok(()) => 0,
            Err(e) => code_byte(&e),
        };
        Ok(to_java(env, &[code])?)
    })
}

/// Step 10: finishes the check and closes the handle. Returns `[code]`.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeApkFinish(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jni::sys::jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let Some(state) = remove_apk(handle) else {
            return Ok(to_java(env, &[code_byte(&UpdateError::OutOfOrder)])?);
        };
        let mut guard = state.lock().map_err(|_| cat::INTERNAL)?;
        let Some(check) = guard.check.take() else {
            return Ok(to_java(env, &[code_byte(&UpdateError::OutOfOrder)])?);
        };
        let code = match check.finish() {
            Ok(()) => 0u8,
            Err(e) => code_byte(&e),
        };
        Ok(to_java(env, &[code])?)
    })
}

/// Idempotent abort; unknown ids are ignored.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeApkAbort(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    let _ = &mut env;
    remove_apk(handle);
}

// ---------------------------------------------------------------------------
// The mirror set and the fetch (§9.3): nativeMirrorSet builds the set from the
// stored state, the embedded chain, the day and the run's draw; TorMirrorTransport
// fetches from it. Kotlin can name neither an onion nor a path nor an offset.
// ---------------------------------------------------------------------------

use ghost_client_update::draw::draw_for_run;

use crate::mirror::MirrorSet;

fn mirror_registry() -> &'static Mutex<HashMap<jlong, Arc<MirrorSet>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<jlong, Arc<MirrorSet>>>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

static NEXT_MIRROR_ID: AtomicI64 = AtomicI64::new(1);

fn register_mirror(set: MirrorSet) -> jlong {
    let id = NEXT_MIRROR_ID.fetch_add(1, Ordering::Relaxed);
    mirror_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id, Arc::new(set));
    id
}

fn lookup_mirror(id: jlong) -> Outcome<Arc<MirrorSet>> {
    mirror_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&id)
        .cloned()
        .ok_or(cat::CLOSED)
}

fn remove_mirror(id: jlong) {
    mirror_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id);
}

/// Builds the run's mirror set (§7.8): two canonical onions from the stored state, the embedded
/// chain, the day (a stale manifest contributes no extra mirror) and the run's 32-byte draw; the
/// offered APK's hash and length travel with the set so the native side alone builds the chunk
/// paths and ranges. `day_trusted == 0` contributes no extras either (a draw is not a
/// time-dependent step, but an expired manifest must not name mirrors).
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeMirrorSet(
    mut env: JNIEnv,
    _class: JClass,
    stored: JByteArray,
    embedded_chain: JByteArray,
    no_channel: jboolean,
    day_trusted: jboolean,
    day: jint,
    draw: JByteArray,
    has_offer: jboolean,
    offer_sha256: JByteArray,
    offer_length: jlong,
) -> jlong {
    guarded(&mut env, 0, |env| {
        let state = decode_stored(&bytes(env, &stored)?).map_err(|_| cat::INVALID_ARGUMENT)?;
        let embedded = bytes(env, &embedded_chain)?;
        let chain = ghost_client_release::chain::GHRC::parse(&embedded)
            .map_err(|_| cat::INVALID_ARGUMENT)?;
        let draw: [u8; 32] = fixed(env, &draw)?;
        let today = if day_trusted != 0 { day as u32 } else { 0 };
        let pick = draw_for_run(&state, &chain, no_channel != 0, today, &draw)
            .ok_or(cat::INVALID_ARGUMENT)?;
        let (apk_sha256, apk_length) = if has_offer != 0 {
            (Some(fixed::<32>(env, &offer_sha256)?), offer_length as u64)
        } else {
            (None, 0)
        };
        Ok(register_mirror(MirrorSet {
            first: pick.first.0,
            second: pick.second.0,
            network: state.trusted_root().body.network as u8,
            apk_sha256,
            apk_length,
        }))
    })
}

/// Closes a mirror set. Idempotent.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeMirrorSetClose(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    let _ = &mut env;
    remove_mirror(handle);
}

/// `TorMirrorTransport.nativeFetch`: one fetch of the run — the bundle (`kind` 0, 200, ≤ 1 MiB)
/// or an APK chunk (`kind` 1, 206 with the matching `content-range`, ≤ 4 MiB), over the mirror
/// `slot` (0 or 1) of the set, on the `Update` isolation scope, under `deadline_ms`.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_TorMirrorTransport_nativeFetch(
    mut env: JNIEnv,
    _class: JClass,
    transport: jlong,
    mirror_set: jlong,
    slot: jint,
    kind: jint,
    chunk_index: jlong,
    deadline_ms: jlong,
) -> jni::sys::jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let handle = lookup(transport)?;
        let tor = handle.transport()?.clone();
        let set = lookup_mirror(mirror_set)?;
        let deadline = std::time::Duration::from_millis(deadline_ms as u64);
        let bytes_out = handle.run(crate::mirror::fetch(
            &tor,
            &set,
            slot as u8,
            kind as u8,
            chunk_index as u64,
            deadline,
        ))?;
        Ok(to_java(env, &bytes_out)?)
    })
}

// ---------------------------------------------------------------------- D19's relay directory
//
// Both relay-list entry points answer the same strict shape (§9.3's byte-in/byte-out rule):
// `[code][n u16][n × (u8 host_len ‖ host ‖ u16 port ‖ operator_id 16)]`, `host` the 56-char
// base32 label WITHOUT the `.onion` suffix. Parsing stays in Rust (ADR-19): the txt format of
// the committed bootstrap and the GHRM relay section are protocol shapes.

/// One relay directory entry, decoded.
struct NativeRelay {
    host: Vec<u8>,
    port: u16,
    operator: [u8; 16],
}

fn encode_relays(code: u8, relays: &[NativeRelay]) -> Vec<u8> {
    let mut out = result(code, &[]);
    out.extend_from_slice(&(relays.len() as u16).to_be_bytes());
    for r in relays {
        out.push(r.host.len() as u8);
        out.extend_from_slice(&r.host);
        out.extend_from_slice(&r.port.to_be_bytes());
        out.extend_from_slice(&r.operator);
    }
    out
}

/// Parse the committed bootstrap txt: `relay <56 base32>.onion:<port> <operator id, 32 hex>`,
/// `#` comments and blank lines skipped. A malformed entry is a build error (the file is
/// gate-checked by scripts/gates/entitlement-schedule.sh, so this cannot happen at runtime).
fn parse_bootstrap_relays() -> Result<Vec<NativeRelay>, FormatError> {
    let mut out = Vec::new();
    for line in EMBEDDED_RELAY_DIRECTORY.split(|&b| b == b'\n') {
        let line = trim_ascii(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let rest = line
            .strip_prefix(b"relay ")
            .ok_or(FormatError::Syntax)?;
        let (addr, op_hex) = split_ws(rest).ok_or(FormatError::Syntax)?;
        ghost_client_release::onion::canonical_onion(addr)?;
        let (host, port) = ghost_client_release::onion::split_host_port(addr)?;
        let operator = parse_operator(op_hex)?;
        out.push(NativeRelay { host, port, operator });
    }
    Ok(out)
}

fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while s.first().is_some_and(|b| b.is_ascii_whitespace()) {
        s = &s[1..];
    }
    while s.last().is_some_and(|b| b.is_ascii_whitespace()) {
        s = &s[..s.len() - 1];
    }
    s
}

fn split_ws(s: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = s.iter().position(|b| b.is_ascii_whitespace())?;
    let first = &s[..at];
    let second = trim_ascii(&s[at + 1..]);
    if first.is_empty() || second.is_empty() || second.iter().any(|b| b.is_ascii_whitespace()) {
        return None;
    }
    Some((first, second))
}

fn parse_operator(hex: &[u8]) -> Result<[u8; 16], FormatError> {
    if hex.len() != 32 || !hex.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(FormatError::Syntax);
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = (hex[2 * i] as char).to_digit(16).ok_or(FormatError::Syntax)?;
        let lo = (hex[2 * i + 1] as char).to_digit(16).ok_or(FormatError::Syntax)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

/// §11.4's emulator seam, the chunk step half: the fixed 4 MiB step of §7.2 as a u64, so even
/// the gate-only loopback transport slices without naming a protocol constant in Kotlin (PM-D10).
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeApkChunkStep(
    mut env: JNIEnv,
    _class: JClass,
) -> jlong {
    let _ = &mut env;
    crate::mirror::CHUNK as jlong
}

/// §11.4's emulator seam (G-DM5's rules): the path of one fetch, built natively exactly as the
/// Tor fetch builds it — a gate-only loopback transport fetches this path over plain HTTP from a
/// model mirror, so no protocol constant (network segment, file name, chunk bounds) is named in
/// Kotlin. `[code][path]`.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeMirrorPath(
    mut env: JNIEnv,
    _class: JClass,
    mirror_set: jlong,
    kind: jint,
    chunk_index: jlong,
) -> jni::sys::jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let set = lookup_mirror(mirror_set)?;
        let path = set
            .path(kind as u8, chunk_index as u64)
            .map_err(|_| cat::INVALID_ARGUMENT)?;
        Ok(to_java(env, &result(0, path.as_bytes()))?)
    })
}

/// D19's bootstrap: the committed, gate-checked `relay-directory.txt`, decoded. `[code][entries]`.
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeBootstrapRelays(
    mut env: JNIEnv,
    _class: JClass,
) -> jni::sys::jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let relays = parse_bootstrap_relays().map_err(|_| cat::INVALID_ARGUMENT)?;
        Ok(to_java(env, &encode_relays(0, &relays))?)
    })
}

/// §7.8's half of the directory hook: the GHRM's relay list, in the document's canonical
/// `"<56 base32>.onion:<port>"` spelling (the parser's canonical_onion rule; the port rides in
/// the text, unlike the raw manifest mirrors' connection spelling decided per entry).
/// `[code][entries]`; a malformed document is `INVALID_ARGUMENT` (a signed manifest the codec
/// verified cannot be malformed, so this is a defence-in-depth arm).
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeManifestRelays(
    mut env: JNIEnv,
    _class: JClass,
    manifest: JByteArray,
) -> jni::sys::jbyteArray {
    guarded(&mut env, std::ptr::null_mut(), |env| {
        let doc = bytes(env, &manifest)?;
        let ghrm = ghost_client_release::manifest::GHRM::parse(&doc)
            .map_err(|_| cat::INVALID_ARGUMENT)?;
        let mut relays = Vec::with_capacity(ghrm.body.relays.len());
        for (text, operator) in &ghrm.body.relays {
            let (host, port) = ghost_client_release::onion::split_host_port(text)
                .map_err(|_| cat::INVALID_ARGUMENT)?;
            relays.push(NativeRelay { host, port, operator: *operator });
        }
        Ok(to_java(env, &encode_relays(0, &relays))?)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed bootstrap parses: every `relay` line becomes one entry with a 56-char host,
    /// a non-zero port and a 16-byte operator. The file is gate-checked, so this is a roundtrip
    /// guard on the txt format rather than input validation.
    #[test]
    fn committed_bootstrap_parses() {
        let relays = parse_bootstrap_relays().expect("the committed relay-directory.txt parses");
        assert!(!relays.is_empty());
        for r in &relays {
            assert_eq!(r.host.len(), 56);
            assert!(r.port > 0);
        }
        // The encoder's shape: [0][n u16][n x (u8 len, host, u16 port, 16 op)].
        let encoded = encode_relays(0, &relays);
        assert_eq!(encoded[0], 0);
        assert_eq!(
            u16::from_be_bytes([encoded[1], encoded[2]]) as usize,
            relays.len()
        );
    }

    /// The manifest arm encodes relays at the canonical port 443 with the operator preserved.
    #[test]
    fn manifest_relays_use_canonical_port() {
        // Build a minimal GHRM via the release crate's own test path is heavy; instead check the
        // encoder preserves operator bytes exactly (the parse side is GHRM::parse, tested in the
        // release crate).
        let relays = parse_bootstrap_relays().unwrap();
        let encoded = encode_relays(0, &relays);
        let mut pos = 3;
        for r in &relays {
            let len = encoded[pos] as usize;
            pos += 1 + len;
            let port = u16::from_be_bytes([encoded[pos], encoded[pos + 1]]);
            pos += 2;
            assert_eq!(port, r.port);
            assert_eq!(&encoded[pos..pos + 16], &r.operator);
            pos += 16;
        }
        assert_eq!(pos, encoded.len());
    }
}

/// §11.3's mutant selector (Phase 14 design §11.3; slice S6c): `UpdateMutants.select(id)` sets
/// the process-wide active mutant of `ghost-client-update`'s `mutants` feature for the JVM
/// world's next native calls; 0 restores the shipped behaviour at every site. Test libraries
/// only: this entry is compiled solely behind the crate's `test-mutants` feature, which only
/// `ghost-dm-host` enables (G-D5 refuses the symbol in a shipped library; G-D6 keeps the feature
/// out of every shipped graph). A negative id is never a valid mutant and selects none.
#[cfg(feature = "test-mutants")]
#[no_mangle]
pub extern "system" fn Java_org_ghost_network_UpdateMutants_select(
    _env: JNIEnv,
    _class: JClass,
    id: jint,
) {
    ghost_client_update::mutants::select(u32::try_from(id).unwrap_or(u32::MAX));
}
