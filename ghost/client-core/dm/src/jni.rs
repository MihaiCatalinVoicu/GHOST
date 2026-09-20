//! The closed JNI surface `org.ghost.crypto.bridge.DmNative` (design §2.6, gate G-R6).
//!
//! **Shape.** Every function is `static native`, takes byte arrays and ints, and returns **one**
//! byte array `code(1) || TLV fields`, which Kotlin's `DmResult` decodes. No function performs
//! I/O, reads a clock, logs, or keeps state between calls other than the context handle; none
//! throws. A Rust panic is caught under a silent panic hook installed once per process and
//! returned as [`DmCode::Internal`], which Kotlin turns into `IllegalStateException` (rollback,
//! crash, poison guard) — the hook matters because the **default** hook prints the panic message
//! and its source location to stderr, which the no-logging rule forbids for the DM graph (T3,
//! S0′ V-5).
//!
//! **Value state (§2.5, §7.9).** Every secret Kotlin stores or passes back crosses this boundary
//! wrapped under `session_state_key`, with the associated data of §22.8.3. An envelope that does
//! not open under its binding is [`DmCode::StateCorrupt`]; nothing is cached across calls.
//!
//! **The closed list.** [`CLOSED_LIST`] is the list of §2.6. Every entry names the slice it
//! arrives in, and G-R6 checks both directions: no export outside the list, and every entry marked
//! [`Availability::Exported`] really exported from `libghost_client_net.so`. The functions of the
//! card, bundle, seal and PQ layers are declared here and exported by their own slices (S6, S7,
//! S13), which is what keeps the list closed while it is being filled.

use crate::derive::{self, KemSecret, MessagingBranch, OlmSecret, StateKey};
use crate::olm::pickle::ChainPosition;
use crate::olm::session::{self, Slot, StoredSession};
use crate::provenance::{CardSource, KeyProvenance, SealKey};
use crate::result::DmCode;
use crate::{bundle, card, pq, safety, seal, wrap};
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jint, jlong};
use jni::JNIEnv;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, Once, OnceLock};
use zeroize::Zeroize;

/// Whether a function of the closed list is exported by the current build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    /// Exported from `libghost_client_net.so` today.
    Exported,
    /// On the closed list, delivered by a later slice; nothing may export it before then.
    Declared(&'static str),
}

/// The closed list of §2.6: `(function number, name, availability)`.
///
/// Numbers follow the design's table, and a name that appears twice in one row of that table (for
/// example `ctxOpen`/`ctxClose`) is one entry each.
pub const CLOSED_LIST: &[(u8, &str, Availability)] = &[
    (1, "ctxOpen", Availability::Exported),
    (1, "ctxClose", Availability::Exported),
    (2, "ownCard", Availability::Exported),
    (3, "cardParse", Availability::Declared("S7")),
    (3, "cardDerive", Availability::Declared("S7")),
    (4, "ownReadSecret", Availability::Declared("S6")),
    (5, "bundleCreate", Availability::Exported),
    (6, "bundleOpen", Availability::Declared("S7")),
    (7, "sessionOutbound", Availability::Exported),
    (8, "encrypt", Availability::Exported),
    (9, "sealIntro", Availability::Declared("S7")),
    (10, "sealSym", Availability::Declared("S7")),
    (11, "openOuter", Availability::Declared("S7")),
    (12, "openIntro", Availability::Declared("S7")),
    (13, "decrypt", Availability::Exported),
    (14, "sessionInbound", Availability::Exported),
    (15, "pairKeys", Availability::Declared("S7")),
    (16, "pqRootSeal", Availability::Declared("S13")),
    (16, "pqRootOpen", Availability::Declared("S13")),
    (17, "safetyNumber", Availability::Exported),
    (18, "l0Encode", Availability::Declared("S7")),
    (18, "l0Decode", Availability::Declared("S7")),
    (19, "chainPosition", Availability::Exported),
    (20, "sessionPrune", Availability::Exported),
];

/// The TLV field tags of the reply. Kotlin's `DmResult` decodes exactly this set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Field {
    /// `ctxOpen`: the context handle, `i64` big-endian.
    Handle = 0x01,
    /// A wrapped `olm_session.state_env`.
    State = 0x02,
    /// A raw 32-byte session id.
    SessionId = 0x03,
    /// Olm message bytes.
    L1 = 0x04,
    /// L0 content bytes.
    L0 = 0x05,
    /// Bit 0: the output is a PreKey message. Bit 1: the session is acknowledged.
    Flags = 0x06,
    /// Which stored slot decrypted: 0 = current, 1 = previous.
    SlotUsed = 0x07,
    /// A wrapped `reply_seed` (`olm_session.prov_env`).
    ReplySeed = 0x08,
    /// A receiver chain's next index, `u64` big-endian.
    ChainIndex = 0x09,
    /// How many skipped keys `sessionPrune` removed, `u32` big-endian.
    Pruned = 0x0a,
    /// The 60 safety-number digits, ASCII.
    Digits = 0x0b,
    /// The 65-byte scannable safety number.
    Scannable = 0x0c,
    /// The own contact card v2, 131 bytes.
    Card = 0x0d,
    /// The inbox namespace `X_i`.
    InboxNamespace = 0x0e,
    /// The bundle namespace `P_i`.
    BundleNamespace = 0x0f,
    /// The recognition key of `KIO_i` (§6.2 rule R-S6).
    RecognitionIntro = 0x10,
    /// The recognition key of `KB_i`.
    RecognitionBundle = 0x11,
    /// The own Olm identity public key.
    OlmIdentity = 0x12,
    /// A sealed blob of a bucket size (here: the 4 KiB bundle).
    Blob = 0x13,
    /// A generation's Olm fallback public key `F_g`.
    FallbackPublic = 0x14,
    /// A generation's X-Wing public key `Q_g`.
    XwingPublic = 0x15,
    /// A wrapped `olm_prekey_gen.secrets_env` (`f_g || q_g seed`).
    GenerationSecrets = 0x16,
}

impl Field {
    /// The wire tag.
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// Bit 0 of [`Field::Flags`].
pub const FLAG_PRE_KEY: u8 = 0b0000_0001;
/// Bit 1 of [`Field::Flags`].
pub const FLAG_ACKNOWLEDGED: u8 = 0b0000_0010;

/// A reply under construction: `code(1) || (tag(1) || len(u32_be) || value)*`.
struct Reply(Vec<u8>);

impl Reply {
    fn ok() -> Self {
        Self(vec![DmCode::Ok.as_u8()])
    }

    fn field(mut self, tag: Field, value: &[u8]) -> Self {
        self.0.push(tag.tag());
        let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(value);
        self
    }

    fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

fn code_only(code: DmCode) -> Vec<u8> {
    vec![code.as_u8()]
}

// -------------------------------------------------------------------------------------------
// The DM context (§2.5)
// -------------------------------------------------------------------------------------------

/// The secrets the DM context derives once at unlock and holds in native memory only.
struct DmContext {
    olm_identity: OlmSecret,
    olm_signing: OlmSecret,
    state_key: StateKey,
    /// The branch the card, namespace and read secrets derive from (§3.1).
    messaging: MessagingBranch,
    /// The `ghost1` Ed25519 seed, handed over by `:identity` at unlock (§2.4, X-21).
    identity_seed: [u8; 32],
}

fn registry() -> &'static Mutex<HashMap<i64, DmContext>> {
    static REGISTRY: OnceLock<Mutex<HashMap<i64, DmContext>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_handle() -> i64 {
    static NEXT: AtomicI64 = AtomicI64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Runs `body` with the named context, or reports [`DmCode::CryptoUnavailable`] for a closed or
/// foreign handle (§2.5).
fn with_context<T>(
    handle: jlong,
    body: impl FnOnce(&DmContext) -> Result<T, DmCode>,
) -> Result<T, DmCode> {
    let guard = registry().lock().map_err(|_| DmCode::Internal)?;
    let context = guard.get(&handle).ok_or(DmCode::CryptoUnavailable)?;
    body(context)
}

fn quiet_panics() {
    static QUIET: Once = Once::new();
    QUIET.call_once(|| std::panic::set_hook(Box::new(|_| {})));
}

/// Runs a JNI body and turns its outcome into the reply array. A panic becomes `INTERNAL`; a
/// failure to allocate the reply array leaves a null return, which Kotlin reads as `INTERNAL`.
fn guarded(
    env: &mut JNIEnv,
    body: impl FnOnce(&mut JNIEnv) -> Result<Vec<u8>, DmCode>,
) -> jbyteArray {
    quiet_panics();
    let reply = match catch_unwind(AssertUnwindSafe(|| body(env))) {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(code)) => code_only(code),
        Err(_) => code_only(DmCode::Internal),
    };
    match env.byte_array_from_slice(&reply) {
        Ok(array) => array.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn bytes(env: &JNIEnv, array: &JByteArray) -> Result<Vec<u8>, DmCode> {
    env.convert_byte_array(array)
        .map_err(|_| DmCode::NonCanonical)
}

fn fixed<const N: usize>(env: &JNIEnv, array: &JByteArray) -> Result<[u8; N], DmCode> {
    bytes(env, array)?
        .as_slice()
        .try_into()
        .map_err(|_| DmCode::NonCanonical)
}

fn day(today: jint) -> Result<u32, DmCode> {
    u32::try_from(today).map_err(|_| DmCode::NonCanonical)
}

// -------------------------------------------------------------------------------------------
// Function bodies. The `export_jni!` macro wraps each one in a `#[no_mangle] extern "system"`
// entry point inside `ghost-client-net`, so the closed list stays visible there (§2.3).
// -------------------------------------------------------------------------------------------

/// §2.6 function 1: `ctxOpen(messagingBranch32, identitySeed32, sessionStateKey32) -> handle`.
pub fn ctx_open(
    env: &mut JNIEnv,
    messaging_branch: &JByteArray,
    identity_seed: &JByteArray,
    state_key: &JByteArray,
) -> Result<Vec<u8>, DmCode> {
    let messaging = MessagingBranch::from_bytes(fixed::<32>(env, messaging_branch)?);
    let identity_seed = fixed::<32>(env, identity_seed)?;
    let state_key = StateKey::from_bytes(fixed::<32>(env, state_key)?);
    let context = DmContext {
        olm_identity: derive::derive_olm_identity(&messaging),
        olm_signing: derive::derive_olm_account_signing(&messaging),
        state_key,
        messaging,
        identity_seed,
    };
    let handle = next_handle();
    registry()
        .lock()
        .map_err(|_| DmCode::Internal)?
        .insert(handle, context);
    Ok(Reply::ok()
        .field(Field::Handle, &handle.to_be_bytes())
        .into_bytes())
}

/// §2.6 function 1: `ctxClose(handle)`. Zeroising is the `Zeroize` drop of the held secrets; a
/// second close is [`DmCode::CryptoUnavailable`], never a crash.
pub fn ctx_close(handle: jlong) -> Result<Vec<u8>, DmCode> {
    let removed = registry()
        .lock()
        .map_err(|_| DmCode::Internal)?
        .remove(&handle);
    removed.ok_or(DmCode::CryptoUnavailable)?;
    Ok(Reply::ok().into_bytes())
}

/// §2.6 function 2: `ownCard(h, cardIndex)`. The card, its two namespaces, the recognition keys
/// of `KIO_i` and `KB_i` (Kotlin holds **only** recognition keys in clear, rule R-S6) and the own
/// Olm identity.
///
/// Exported by S4b rather than S6 because the session functions above are useless without a way to
/// learn the own Olm identity, which is what a peer's `sessionInbound` pins.
pub fn own_card(env: &mut JNIEnv, handle: jlong, card_index: jint) -> Result<Vec<u8>, DmCode> {
    let _ = env;
    let card_index = u16::try_from(card_index).map_err(|_| DmCode::InvalidCard)?;
    with_context(handle, |context| {
        let card_secret = derive::derive_card_secret(&context.messaging, card_index);
        let card = card::build(&context.identity_seed, card_index, &card_secret);
        let intro = derive::derive_card_value(&card_secret, derive::CardLabel::IntroOuter);
        let bundle_key = derive::derive_card_value(&card_secret, derive::CardLabel::BundleSeal);
        let intro_key = SealKey::new(intro, KeyProvenance::Card(CardSource::InPerson));
        let bundle_seal = SealKey::new(bundle_key, KeyProvenance::Card(CardSource::InPerson));
        Ok(Reply::ok()
            .field(Field::Card, &card.encode())
            .field(
                Field::InboxNamespace,
                &derive::derive_inbox_namespace(&card_secret),
            )
            .field(
                Field::BundleNamespace,
                &derive::derive_bundle_namespace(&card_secret),
            )
            .field(Field::RecognitionIntro, &seal::recognition_key(&intro_key))
            .field(
                Field::RecognitionBundle,
                &seal::recognition_key(&bundle_seal),
            )
            .field(
                Field::OlmIdentity,
                &derive::olm_identity_public(&context.olm_identity),
            )
            .into_bytes())
    })
}

/// §2.6 function 5: `bundleCreate(h, cardIndex, week, rank, genId)`. A fresh generation — an Olm
/// fallback key and an X-Wing key, both random (§3.1 "Random, never derived") — signed into a
/// bundle v2 and sealed under `KB_i` into one 4 KiB blob.
///
/// Exported by S4b rather than S6 for the same reason as [`own_card`]: a first flight needs a
/// generation, and the JVM session tests must build one through the real surface.
pub fn bundle_create(
    env: &mut JNIEnv,
    handle: jlong,
    card_index: jint,
    bundle_week: jlong,
    bundle_rank: jint,
    gen_id: jint,
) -> Result<Vec<u8>, DmCode> {
    let _ = env;
    let card_index = u16::try_from(card_index).map_err(|_| DmCode::InvalidCard)?;
    let bundle_week = u64::try_from(bundle_week).map_err(|_| DmCode::NonCanonical)?;
    let bundle_rank = u16::try_from(bundle_rank).map_err(|_| DmCode::NonCanonical)?;
    let gen_id = gen_id as u32;
    with_context(handle, |context| {
        let mut fallback_secret = [0u8; 32];
        let mut xwing_seed = [0u8; 32];
        pq::fill_random(&mut fallback_secret);
        pq::fill_random(&mut xwing_seed);
        let fallback_public = derive::olm_identity_public(&OlmSecret::from_bytes(fallback_secret));
        let xwing = pq::keygen(&KemSecret::from_bytes(xwing_seed))?;

        let plain = bundle::build(
            &context.identity_seed,
            &bundle::BundleFields {
                card_index,
                bundle_week,
                bundle_rank,
                gen_id,
                olm_identity: &derive::olm_identity_public(&context.olm_identity),
                fallback_key: &fallback_public,
                xwing_public: &xwing.public,
            },
        )?;
        let card_secret = derive::derive_card_secret(&context.messaging, card_index);
        let bundle_key = SealKey::new(
            derive::derive_card_value(&card_secret, derive::CardLabel::BundleSeal),
            KeyProvenance::Card(CardSource::InPerson),
        );
        let namespace = derive::derive_bundle_namespace(&card_secret);
        let blob = seal::seal_bundle(&bundle_key, &namespace, &plain)?;

        let mut secrets = Vec::with_capacity(64);
        secrets.extend_from_slice(&fallback_secret);
        secrets.extend_from_slice(&xwing_seed);
        let secrets_env = wrap::wrap(
            &context.state_key,
            wrap::WrapName::Generation,
            &wrap::generation_binding(gen_id, &fallback_public),
            &secrets,
        );
        fallback_secret.zeroize();
        xwing_seed.zeroize();
        secrets.zeroize();

        Ok(Reply::ok()
            .field(Field::Blob, &blob)
            .field(Field::FallbackPublic, &fallback_public)
            .field(Field::XwingPublic, &xwing.public)
            .field(Field::GenerationSecrets, &secrets_env?)
            .into_bytes())
    })
}

/// §2.6 function 7: `sessionOutbound(h, contactId, peerOlmIdentity, peerFallback, today)`.
pub fn session_outbound(
    env: &mut JNIEnv,
    handle: jlong,
    contact_id: &JByteArray,
    peer_identity: &JByteArray,
    peer_fallback: &JByteArray,
    today: jint,
) -> Result<Vec<u8>, DmCode> {
    let contact_id = fixed::<16>(env, contact_id)?;
    let peer_identity = fixed::<32>(env, peer_identity)?;
    let peer_fallback = fixed::<32>(env, peer_fallback)?;
    let today = day(today)?;
    with_context(handle, |context| {
        let mut out = session::session_outbound(
            &context.olm_identity,
            &context.olm_signing,
            &peer_identity,
            &peer_fallback,
            today,
        )?;
        let state_env = wrap::wrap(
            &context.state_key,
            wrap::WrapName::OlmSession,
            &wrap::olm_session_binding(&contact_id, &out.session_id),
            &out.state,
        );
        out.state.zeroize();
        let state_env = state_env?;
        let reply_seed_env = wrap::wrap(
            &context.state_key,
            wrap::WrapName::ReplySeed,
            &wrap::reply_seed_binding(&out.session_id),
            out.reply_seed.as_bytes(),
        )?;
        Ok(Reply::ok()
            .field(Field::State, &state_env)
            .field(Field::SessionId, &out.session_id)
            .field(Field::ReplySeed, &reply_seed_env)
            .into_bytes())
    })
}

/// §2.6 function 8: `encrypt(h, contactId, sessionId, stateEnv, l0, today)`.
pub fn encrypt(
    env: &mut JNIEnv,
    handle: jlong,
    contact_id: &JByteArray,
    session_id: &JByteArray,
    state_env: &JByteArray,
    l0: &JByteArray,
    today: jint,
) -> Result<Vec<u8>, DmCode> {
    let contact_id = fixed::<16>(env, contact_id)?;
    let session_id = fixed::<32>(env, session_id)?;
    let state_env = bytes(env, state_env)?;
    let l0 = bytes(env, l0)?;
    let today = day(today)?;
    with_context(handle, |context| {
        let binding = wrap::olm_session_binding(&contact_id, &session_id);
        let mut state = wrap::unwrap(
            &context.state_key,
            wrap::WrapName::OlmSession,
            &binding,
            &state_env,
        )?;
        let out = session::encrypt(&state, &l0, today);
        state.zeroize();
        let mut out = out?;
        let new_state = wrap::wrap(
            &context.state_key,
            wrap::WrapName::OlmSession,
            &binding,
            &out.state,
        );
        out.state.zeroize();
        let new_state = new_state?;
        let mut flags = 0u8;
        if out.is_pre_key {
            flags |= FLAG_PRE_KEY;
        }
        if out.acknowledged {
            flags |= FLAG_ACKNOWLEDGED;
        }
        Ok(Reply::ok()
            .field(Field::L1, &out.l1)
            .field(Field::State, &new_state)
            .field(Field::Flags, &[flags])
            .into_bytes())
    })
}

/// §2.6 function 13: `decrypt(h, contactId, current(sessionId, env)?, previous(sessionId, env)?,
/// l1, isPreKey, today)`. An absent slot is an empty session id and an empty envelope.
#[allow(clippy::too_many_arguments)]
pub fn decrypt(
    env: &mut JNIEnv,
    handle: jlong,
    contact_id: &JByteArray,
    current_session: &JByteArray,
    current_state: &JByteArray,
    previous_session: &JByteArray,
    previous_state: &JByteArray,
    l1: &JByteArray,
    is_pre_key: jint,
    today: jint,
) -> Result<Vec<u8>, DmCode> {
    let contact_id = fixed::<16>(env, contact_id)?;
    let current = slot(env, current_session, current_state)?;
    let previous = slot(env, previous_session, previous_state)?;
    let l1 = bytes(env, l1)?;
    let today = day(today)?;
    if current.is_none() && previous.is_none() {
        return Err(DmCode::Undecryptable);
    }
    with_context(handle, |context| {
        let mut states = Vec::with_capacity(2);
        for (slot, (session_id, envelope)) in
            [(Slot::Current, &current), (Slot::Previous, &previous)]
                .into_iter()
                .filter_map(|(slot, held)| held.as_ref().map(|pair| (slot, pair)))
        {
            let binding = wrap::olm_session_binding(&contact_id, session_id);
            let state = wrap::unwrap(
                &context.state_key,
                wrap::WrapName::OlmSession,
                &binding,
                envelope,
            )?;
            states.push((slot, *session_id, state));
        }
        let out = {
            let trial: Vec<StoredSession<'_>> = states
                .iter()
                .map(|(slot, _, state)| StoredSession {
                    slot: *slot,
                    state: state.as_slice(),
                })
                .collect();
            session::decrypt(&trial, &l1, is_pre_key != 0, today)
        };
        // The unwrapped states are the session's keys in the clear: they go no further than this
        // call, whatever its outcome (§2.5).
        for (_, _, state) in states.iter_mut() {
            state.zeroize();
        }
        let mut out = out?;
        let (_, session_id, _) = states
            .iter()
            .find(|(slot, _, _)| *slot == out.slot)
            .ok_or(DmCode::StateCorrupt)?;
        let new_state = wrap::wrap(
            &context.state_key,
            wrap::WrapName::OlmSession,
            &wrap::olm_session_binding(&contact_id, session_id),
            &out.state,
        );
        out.state.zeroize();
        let new_state = new_state?;
        let flags = if out.acknowledged {
            FLAG_ACKNOWLEDGED
        } else {
            0
        };
        Ok(Reply::ok()
            .field(Field::L0, &out.plaintext)
            .field(Field::State, &new_state)
            .field(Field::SlotUsed, &[out.slot.as_u8()])
            .field(Field::Flags, &[flags])
            .into_bytes())
    })
}

/// One stored slot as it crosses JNI: its raw session id and its wrapped state envelope.
type StoredSlot = ([u8; 32], Vec<u8>);

/// Decodes one slot argument pair. An absent slot is an empty session id **and** an empty
/// envelope; a session id without an envelope is [`DmCode::StateCorrupt`], because the caller
/// holds a row it cannot open.
fn slot(
    env: &JNIEnv,
    session_id: &JByteArray,
    state_env: &JByteArray,
) -> Result<Option<StoredSlot>, DmCode> {
    let id = bytes(env, session_id)?;
    let envelope = bytes(env, state_env)?;
    if id.is_empty() && envelope.is_empty() {
        return Ok(None);
    }
    let id: [u8; 32] = id.as_slice().try_into().map_err(|_| DmCode::NonCanonical)?;
    if envelope.is_empty() {
        return Err(DmCode::StateCorrupt);
    }
    Ok(Some((id, envelope)))
}

/// §2.6 function 14: `sessionInbound(h, contactId, genId, genSecretsEnv, genFallbackPublic,
/// expectedPeerIdentity, l1, today)`.
#[allow(clippy::too_many_arguments)]
pub fn session_inbound(
    env: &mut JNIEnv,
    handle: jlong,
    contact_id: &JByteArray,
    gen_id: jint,
    gen_secrets_env: &JByteArray,
    gen_fallback_public: &JByteArray,
    expected_peer_identity: &JByteArray,
    l1: &JByteArray,
    today: jint,
) -> Result<Vec<u8>, DmCode> {
    let contact_id = fixed::<16>(env, contact_id)?;
    let gen_id = gen_id as u32;
    let gen_secrets_env = bytes(env, gen_secrets_env)?;
    let gen_fallback_public = fixed::<32>(env, gen_fallback_public)?;
    let expected_peer_identity = fixed::<32>(env, expected_peer_identity)?;
    let l1 = bytes(env, l1)?;
    let today = day(today)?;
    with_context(handle, |context| {
        let mut secrets = wrap::unwrap(
            &context.state_key,
            wrap::WrapName::Generation,
            &wrap::generation_binding(gen_id, &gen_fallback_public),
            &gen_secrets_env,
        )?;
        // `secrets_env` holds the fallback secret and the X-Wing seed (§13.6, 64 bytes wrapped).
        let mut fallback = [0u8; 32];
        let taken = secrets.get(..32).map(|half| fallback.copy_from_slice(half));
        secrets.zeroize();
        taken.ok_or(DmCode::StateCorrupt)?;
        let out = session::session_inbound(
            &context.olm_identity,
            &context.olm_signing,
            fallback,
            &expected_peer_identity,
            &l1,
            today,
        );
        fallback.zeroize();
        let mut out = out?;
        let state_env = wrap::wrap(
            &context.state_key,
            wrap::WrapName::OlmSession,
            &wrap::olm_session_binding(&contact_id, &out.session_id),
            &out.state,
        );
        out.state.zeroize();
        let state_env = state_env?;
        Ok(Reply::ok()
            .field(Field::L0, &out.plaintext)
            .field(Field::State, &state_env)
            .field(Field::SessionId, &out.session_id)
            .into_bytes())
    })
}

/// §2.6 function 17: `safetyNumber(ownIdPk, ownOlm, peerIdPk, peerOlm)`. Stateless: no handle.
pub fn safety_number(
    env: &mut JNIEnv,
    own_identity_pk: &JByteArray,
    own_olm: &JByteArray,
    peer_identity_pk: &JByteArray,
    peer_olm: &JByteArray,
) -> Result<Vec<u8>, DmCode> {
    let own = safety::Party {
        identity_pk: fixed::<32>(env, own_identity_pk)?,
        olm_identity: fixed::<32>(env, own_olm)?,
    };
    let peer = safety::Party {
        identity_pk: fixed::<32>(env, peer_identity_pk)?,
        olm_identity: fixed::<32>(env, peer_olm)?,
    };
    let number = safety::safety_number(&own, &peer);
    Ok(Reply::ok()
        .field(Field::Digits, number.display.as_bytes())
        .field(Field::Scannable, &number.scannable)
        .into_bytes())
}

/// §2.6 function 19: `chainPosition(h, contactId, sessionId, stateEnv, ratchetKey)`. Writes
/// nothing (T28); called during peek, outside any transaction.
pub fn chain_position(
    env: &mut JNIEnv,
    handle: jlong,
    contact_id: &JByteArray,
    session_id: &JByteArray,
    state_env: &JByteArray,
    ratchet_key: &JByteArray,
) -> Result<Vec<u8>, DmCode> {
    let contact_id = fixed::<16>(env, contact_id)?;
    let session_id = fixed::<32>(env, session_id)?;
    let state_env = bytes(env, state_env)?;
    let ratchet_key = fixed::<32>(env, ratchet_key)?;
    with_context(handle, |context| {
        let mut state = wrap::unwrap(
            &context.state_key,
            wrap::WrapName::OlmSession,
            &wrap::olm_session_binding(&contact_id, &session_id),
            &state_env,
        )?;
        let position = session::chain_position(&state, &ratchet_key);
        state.zeroize();
        match position? {
            ChainPosition::Index(index) => Ok(Reply::ok()
                .field(Field::ChainIndex, &index.to_be_bytes())
                .into_bytes()),
            // A result value, not an error (§2.6 function 19).
            ChainPosition::NewChain => Ok(code_only(DmCode::NewChain)),
        }
    })
}

/// §2.6 function 20: `sessionPrune(h, contactId, sessionId, stateEnv, today)`.
pub fn session_prune(
    env: &mut JNIEnv,
    handle: jlong,
    contact_id: &JByteArray,
    session_id: &JByteArray,
    state_env: &JByteArray,
    today: jint,
) -> Result<Vec<u8>, DmCode> {
    let contact_id = fixed::<16>(env, contact_id)?;
    let session_id = fixed::<32>(env, session_id)?;
    let state_env = bytes(env, state_env)?;
    let today = day(today)?;
    with_context(handle, |context| {
        let binding = wrap::olm_session_binding(&contact_id, &session_id);
        let mut state = wrap::unwrap(
            &context.state_key,
            wrap::WrapName::OlmSession,
            &binding,
            &state_env,
        )?;
        let outcome = session::session_prune(&state, today);
        state.zeroize();
        let (mut pruned, removed) = outcome?;
        let new_state = wrap::wrap(
            &context.state_key,
            wrap::WrapName::OlmSession,
            &binding,
            &pruned,
        );
        pruned.zeroize();
        let new_state = new_state?;
        let removed = u32::try_from(removed).unwrap_or(u32::MAX);
        Ok(Reply::ok()
            .field(Field::State, &new_state)
            .field(Field::Pruned, &removed.to_be_bytes())
            .into_bytes())
    })
}

/// The entry points, for the export macro. Each is `pub` so `ghost-client-net` can wrap it.
pub mod entry {
    use super::*;

    /// `ctxOpen`
    pub fn ctx_open<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        messaging_branch: JByteArray<'local>,
        identity_seed: JByteArray<'local>,
        state_key: JByteArray<'local>,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::ctx_open(env, &messaging_branch, &identity_seed, &state_key)
        })
    }

    /// `ctxClose`
    pub fn ctx_close<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
    ) -> jbyteArray {
        guarded(&mut env, |_| super::ctx_close(handle))
    }

    /// `ownCard`
    pub fn own_card<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        card_index: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::own_card(env, handle, card_index))
    }

    /// `bundleCreate`
    pub fn bundle_create<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        card_index: jint,
        bundle_week: jlong,
        bundle_rank: jint,
        gen_id: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::bundle_create(env, handle, card_index, bundle_week, bundle_rank, gen_id)
        })
    }

    /// `sessionOutbound`
    pub fn session_outbound<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        contact_id: JByteArray<'local>,
        peer_identity: JByteArray<'local>,
        peer_fallback: JByteArray<'local>,
        today: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::session_outbound(
                env,
                handle,
                &contact_id,
                &peer_identity,
                &peer_fallback,
                today,
            )
        })
    }

    /// `encrypt`
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        contact_id: JByteArray<'local>,
        session_id: JByteArray<'local>,
        state_env: JByteArray<'local>,
        l0: JByteArray<'local>,
        today: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::encrypt(
                env,
                handle,
                &contact_id,
                &session_id,
                &state_env,
                &l0,
                today,
            )
        })
    }

    /// `decrypt`
    #[allow(clippy::too_many_arguments)]
    pub fn decrypt<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        contact_id: JByteArray<'local>,
        current_session: JByteArray<'local>,
        current_state: JByteArray<'local>,
        previous_session: JByteArray<'local>,
        previous_state: JByteArray<'local>,
        l1: JByteArray<'local>,
        is_pre_key: jint,
        today: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::decrypt(
                env,
                handle,
                &contact_id,
                &current_session,
                &current_state,
                &previous_session,
                &previous_state,
                &l1,
                is_pre_key,
                today,
            )
        })
    }

    /// `sessionInbound`
    #[allow(clippy::too_many_arguments)]
    pub fn session_inbound<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        contact_id: JByteArray<'local>,
        gen_id: jint,
        gen_secrets_env: JByteArray<'local>,
        gen_fallback_public: JByteArray<'local>,
        expected_peer_identity: JByteArray<'local>,
        l1: JByteArray<'local>,
        today: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::session_inbound(
                env,
                handle,
                &contact_id,
                gen_id,
                &gen_secrets_env,
                &gen_fallback_public,
                &expected_peer_identity,
                &l1,
                today,
            )
        })
    }

    /// `safetyNumber`
    pub fn safety_number<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        own_identity_pk: JByteArray<'local>,
        own_olm: JByteArray<'local>,
        peer_identity_pk: JByteArray<'local>,
        peer_olm: JByteArray<'local>,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::safety_number(
                env,
                &own_identity_pk,
                &own_olm,
                &peer_identity_pk,
                &peer_olm,
            )
        })
    }

    /// `chainPosition`
    pub fn chain_position<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        contact_id: JByteArray<'local>,
        session_id: JByteArray<'local>,
        state_env: JByteArray<'local>,
        ratchet_key: JByteArray<'local>,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::chain_position(
                env,
                handle,
                &contact_id,
                &session_id,
                &state_env,
                &ratchet_key,
            )
        })
    }

    /// `sessionPrune`
    pub fn session_prune<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        contact_id: JByteArray<'local>,
        session_id: JByteArray<'local>,
        state_env: JByteArray<'local>,
        today: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::session_prune(env, handle, &contact_id, &session_id, &state_env, today)
        })
    }
}

/// Exports the DM JNI entry points from the calling crate (design §2.3).
///
/// `ghost-client-net` invokes this in `jni_bridge.rs` so the closed list stays visible there for
/// G-R6, and `ghost-dm-host` invokes it too so the JVM tests call exactly the shipped code. S0′
/// V-5 verified that macro exports and a dependency's `#[no_mangle]` exports both survive linking
/// and `strip = "symbols"` on arm64-v8a and x86_64, so no explicit wrapper functions are needed.
#[macro_export]
macro_rules! export_jni {
    () => {
        $crate::export_jni!(@one ctxOpen ctx_open);
        $crate::export_jni!(@one ctxClose ctx_close);
        $crate::export_jni!(@one ownCard own_card);
        $crate::export_jni!(@one bundleCreate bundle_create);
        $crate::export_jni!(@one sessionOutbound session_outbound);
        $crate::export_jni!(@one encrypt encrypt);
        $crate::export_jni!(@one decrypt decrypt);
        $crate::export_jni!(@one sessionInbound session_inbound);
        $crate::export_jni!(@one safetyNumber safety_number);
        $crate::export_jni!(@one chainPosition chain_position);
        $crate::export_jni!(@one sessionPrune session_prune);
    };
    (@one $java:ident $rust:ident) => {
        $crate::paste_export!($java, $rust);
    };
}

/// Emits one `#[no_mangle] extern "system"` alias. Kept separate so the JNI name is written out
/// literally: `#[no_mangle]` takes no computed name, and a proc-macro dependency is not approved
/// for this crate (ADR-19: no new crate outside the DM stack).
#[macro_export]
macro_rules! paste_export {
    (ctxOpen, $rust:ident) => {
        /// One entry point of the closed JNI surface (design §2.6); the body is in
        /// [`crate::jni::entry`].
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_ctxOpen<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            a: ::jni::objects::JByteArray<'local>,
            b: ::jni::objects::JByteArray<'local>,
            c: ::jni::objects::JByteArray<'local>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::ctx_open(env, class, a, b, c)
        }
    };
    (ctxClose, $rust:ident) => {
        /// One entry point of the closed JNI surface (design §2.6); the body is in
        /// [`crate::jni::entry`].
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_ctxClose<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::ctx_close(env, class, handle)
        }
    };
    (ownCard, $rust:ident) => {
        /// One entry point of the closed JNI surface (design §2.6); the body is in
        /// [`crate::jni::entry`].
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_ownCard<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            card_index: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::own_card(env, class, handle, card_index)
        }
    };
    (bundleCreate, $rust:ident) => {
        /// One entry point of the closed JNI surface (design §2.6); the body is in
        /// [`crate::jni::entry`].
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_bundleCreate<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            card_index: ::jni::sys::jint,
            bundle_week: ::jni::sys::jlong,
            bundle_rank: ::jni::sys::jint,
            gen_id: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::bundle_create(
                env,
                class,
                handle,
                card_index,
                bundle_week,
                bundle_rank,
                gen_id,
            )
        }
    };
    (sessionOutbound, $rust:ident) => {
        /// One entry point of the closed JNI surface (design §2.6); the body is in
        /// [`crate::jni::entry`].
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_sessionOutbound<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'local>,
            b: ::jni::objects::JByteArray<'local>,
            c: ::jni::objects::JByteArray<'local>,
            today: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::session_outbound(env, class, handle, a, b, c, today)
        }
    };
    (encrypt, $rust:ident) => {
        /// One entry point of the closed JNI surface (design §2.6); the body is in
        /// [`crate::jni::entry`].
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_encrypt<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'local>,
            b: ::jni::objects::JByteArray<'local>,
            c: ::jni::objects::JByteArray<'local>,
            d: ::jni::objects::JByteArray<'local>,
            today: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::encrypt(env, class, handle, a, b, c, d, today)
        }
    };
    (decrypt, $rust:ident) => {
        /// One entry point of the closed JNI surface (design §2.6); the body is in
        /// [`crate::jni::entry`].
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_decrypt<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'local>,
            b: ::jni::objects::JByteArray<'local>,
            c: ::jni::objects::JByteArray<'local>,
            d: ::jni::objects::JByteArray<'local>,
            e: ::jni::objects::JByteArray<'local>,
            f: ::jni::objects::JByteArray<'local>,
            is_pre_key: ::jni::sys::jint,
            today: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::decrypt(env, class, handle, a, b, c, d, e, f, is_pre_key, today)
        }
    };
    (sessionInbound, $rust:ident) => {
        /// One entry point of the closed JNI surface (design §2.6); the body is in
        /// [`crate::jni::entry`].
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_sessionInbound<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'local>,
            gen_id: ::jni::sys::jint,
            b: ::jni::objects::JByteArray<'local>,
            c: ::jni::objects::JByteArray<'local>,
            d: ::jni::objects::JByteArray<'local>,
            e: ::jni::objects::JByteArray<'local>,
            today: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::session_inbound(env, class, handle, a, gen_id, b, c, d, e, today)
        }
    };
    (safetyNumber, $rust:ident) => {
        /// One entry point of the closed JNI surface (design §2.6); the body is in
        /// [`crate::jni::entry`].
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_safetyNumber<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            a: ::jni::objects::JByteArray<'local>,
            b: ::jni::objects::JByteArray<'local>,
            c: ::jni::objects::JByteArray<'local>,
            d: ::jni::objects::JByteArray<'local>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::safety_number(env, class, a, b, c, d)
        }
    };
    (chainPosition, $rust:ident) => {
        /// One entry point of the closed JNI surface (design §2.6); the body is in
        /// [`crate::jni::entry`].
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_chainPosition<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'local>,
            b: ::jni::objects::JByteArray<'local>,
            c: ::jni::objects::JByteArray<'local>,
            d: ::jni::objects::JByteArray<'local>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::chain_position(env, class, handle, a, b, c, d)
        }
    };
    (sessionPrune, $rust:ident) => {
        /// One entry point of the closed JNI surface (design §2.6); the body is in
        /// [`crate::jni::entry`].
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_sessionPrune<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'local>,
            b: ::jni::objects::JByteArray<'local>,
            c: ::jni::objects::JByteArray<'local>,
            today: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::session_prune(env, class, handle, a, b, c, today)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_closed_list_has_no_duplicate_name_and_covers_every_function_number() {
        let mut names: Vec<&str> = CLOSED_LIST.iter().map(|(_, name, _)| *name).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(
            names.len(),
            count,
            "a name appears twice on the closed list"
        );
        for number in 1..=20u8 {
            assert!(
                CLOSED_LIST.iter().any(|(n, _, _)| *n == number),
                "function {number} of design §2.6 is missing from the closed list"
            );
        }
    }

    #[test]
    fn the_field_tags_are_distinct() {
        let fields = [
            Field::Handle,
            Field::State,
            Field::SessionId,
            Field::L1,
            Field::L0,
            Field::Flags,
            Field::SlotUsed,
            Field::ReplySeed,
            Field::ChainIndex,
            Field::Pruned,
            Field::Digits,
            Field::Scannable,
        ];
        let mut tags: Vec<u8> = fields.iter().map(|field| field.tag()).collect();
        tags.sort_unstable();
        let count = tags.len();
        tags.dedup();
        assert_eq!(tags.len(), count);
    }

    #[test]
    fn a_reply_is_a_code_then_length_prefixed_fields() {
        let reply = Reply::ok()
            .field(Field::SlotUsed, &[1])
            .field(Field::Pruned, &7u32.to_be_bytes())
            .into_bytes();
        assert_eq!(
            reply,
            vec![
                0x00, // OK
                0x07, 0, 0, 0, 1, 1, // slot used
                0x0a, 0, 0, 0, 4, 0, 0, 0, 7, // pruned
            ]
        );
    }
}
