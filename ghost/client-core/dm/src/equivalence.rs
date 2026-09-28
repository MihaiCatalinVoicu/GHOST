//! The host/Android equivalence entry point (Phase 9 design §15.9 item 7, RG-2, V-16; §22.8.10
//! point 6; slice S12). **Test builds only**: this module exists with the `test-vectors` feature,
//! which only `ghost-dm-host` enables — the host library the JVM tests load and, cross-compiled for
//! `x86_64-linux-android`, the emulator's test library. G-R2 keeps the feature out of every shipped
//! graph, and G-R6 checks that a shipped library exports no `DmEquivalence` symbol.
//!
//! One function, [`run`]: a case **kind** and its input bytes in, the output bytes out, with no
//! randomness, no clock and no state between calls. Every operation the design lists as
//! deterministic is reachable through a kind: the derivations and the card codec, the MSC3814
//! encoder and the identity keys vodozemac reports for it, X-Wing key generation from a seed and
//! `encapsulate_with`/decapsulation, every seal mode with fixed salts and KEM randomness and its
//! opening, Olm decryption and normal-message encryption from stored states, the prune, safety
//! numbers, state wrapping and the L0 codec. **Refusals are outputs too**: a result code is the
//! first byte of every answer, so a device that refuses what the host accepts is a difference.
//!
//! The same deterministic inputs run on both builds (the case file
//! `protocol/test-vectors/dm_equivalence.txt`): `dm-emulator.yml` records the host's outputs through
//! JNI on `ghost-dm-host` (the JVM test `DmEquivalenceHostTest`), then replays the file on the
//! emulator's library in the same job and checkout and compares byte for byte (design §22.17 item 8).
//!
//! **Framing.** An input is a sequence of fields, each `u32_be(len) ‖ bytes`; an output is
//! `code(1) ‖` fields in the same framing. A kind that reads a field the input does not carry
//! answers [`DmCode::NonCanonical`].

use crate::card;
use crate::derive::{self, CardLabel, KemSecret, MessagingBranch, ReplySeed, StateKey};
use crate::olm::account::{self, AccountSecrets};
use crate::olm::session::{self, Slot, StoredSession};
use crate::pq;
use crate::provenance::{CardSource, KeyProvenance, SealKey};
use crate::result::{DmCode, DmResult};
use crate::safety::{self, Party};
use crate::seal::{self, IntroContext, IntroSender, SealMode};
use crate::wrap::{self, WrapName};
use crate::{bundle, codec};

/// The case kinds of `dm_equivalence.txt`.
pub mod kind {
    /// The seed-branch derivations of §3.1 and the card-level values of §3.2.
    pub const DERIVE: u8 = 0x01;
    /// Card v2 built from a seed and a branch, its link and its re-parse (§3.3).
    pub const CARD_BUILD: u8 = 0x02;
    /// The fail-closed card parser over arbitrary bytes (§3.3), refusals included.
    pub const CARD_PARSE: u8 = 0x03;
    /// The MSC3814 dehydrated-pickle encoder and the identity keys vodozemac reports (§2.2).
    pub const ACCOUNT: u8 = 0x04;
    /// X-Wing key generation, encapsulation with given randomness and decapsulation (§9.2).
    pub const XWING: u8 = 0x05;
    /// X-Wing decapsulation of arbitrary bytes, refusals included.
    pub const XWING_DECAPS: u8 = 0x06;
    /// Pair mode with a given salt, and its opening (§6.3).
    pub const SEAL_PAIR: u8 = 0x07;
    /// Provisional mode with a given salt, and its opening (§6.7).
    pub const SEAL_PROVISIONAL: u8 = 0x08;
    /// Bundle v2 built, sealed with a given salt, and opened (§5.3).
    pub const SEAL_BUNDLE: u8 = 0x09;
    /// The symmetric opener over arbitrary blobs, refusals included (§6.5).
    pub const OPEN_SYMMETRIC: u8 = 0x0a;
    /// The intro mode with a given salt and KEM randomness, and both of its layers opened (§6.4).
    pub const SEAL_INTRO: u8 = 0x0b;
    /// The L0 decoder and the re-encoding of what it decoded (§7.1), refusals included.
    pub const L0_DECODE: u8 = 0x0c;
    /// Safety number v1 (§8.4).
    pub const SAFETY: u8 = 0x0d;
    /// State wrapping with a given nonce, and the unwrap (§2.5, §22.8.3).
    pub const WRAP: u8 = 0x0e;
    /// Olm decryption from a stored state, with the state after the step (§8.1).
    pub const OLM_DECRYPT: u8 = 0x0f;
    /// Olm normal-message encryption from a stored state whose sending ratchet is active.
    pub const OLM_ENCRYPT: u8 = 0x10;
    /// The skipped-key prune of V-15 on a stored state (§7.7 point 4).
    pub const OLM_PRUNE: u8 = 0x11;
    /// The comparator's control (§15.9 item 7): SHA-256 of the input and nothing else. The
    /// replaying side flips one byte of this case's input, and the comparison must report it.
    pub const CONTROL: u8 = 0xff;
}

/// Runs one case. Never panics on any input: a panic inside is caught by the JNI shim as
/// `INTERNAL`, which is then an output like any other code.
pub fn run(case_kind: u8, input: &[u8]) -> Vec<u8> {
    match dispatch(case_kind, &mut Fields::new(input)) {
        Ok(fields) => {
            let mut out = vec![DmCode::Ok.as_u8()];
            for field in fields {
                push(&mut out, &field);
            }
            out
        }
        Err(code) => vec![code.as_u8()],
    }
}

fn push(out: &mut Vec<u8>, field: &[u8]) {
    let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
}

/// Frames `fields` as an input: the inverse of the reader below, for the case generator.
pub fn frame(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields {
        push(&mut out, field);
    }
    out
}

struct Fields<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Fields<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn next(&mut self) -> DmResult<&'a [u8]> {
        let head = self
            .bytes
            .get(self.at..self.at + 4)
            .ok_or(DmCode::NonCanonical)?;
        let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
        let start = self.at + 4;
        let body = self
            .bytes
            .get(start..start + len)
            .ok_or(DmCode::NonCanonical)?;
        self.at = start + len;
        Ok(body)
    }

    fn fixed<const N: usize>(&mut self) -> DmResult<[u8; N]> {
        self.next()?.try_into().map_err(|_| DmCode::NonCanonical)
    }

    fn u16(&mut self) -> DmResult<u16> {
        Ok(u16::from_be_bytes(self.fixed::<2>()?))
    }

    fn u32(&mut self) -> DmResult<u32> {
        Ok(u32::from_be_bytes(self.fixed::<4>()?))
    }

    fn u64(&mut self) -> DmResult<u64> {
        Ok(u64::from_be_bytes(self.fixed::<8>()?))
    }

    fn u8(&mut self) -> DmResult<u8> {
        Ok(self.fixed::<1>()?[0])
    }
}

fn pq_key(material: [u8; 32]) -> SealKey {
    SealKey::new(material, KeyProvenance::Kem.transported_under())
}

fn card_key(material: [u8; 32]) -> SealKey {
    SealKey::new(material, KeyProvenance::Card(CardSource::InPerson))
}

fn wrap_name(code: u8) -> DmResult<WrapName> {
    WrapName::ALL
        .get(usize::from(code))
        .copied()
        .ok_or(DmCode::NonCanonical)
}

#[allow(clippy::too_many_lines)]
fn dispatch(case_kind: u8, f: &mut Fields<'_>) -> DmResult<Vec<Vec<u8>>> {
    match case_kind {
        kind::DERIVE => {
            let m = MessagingBranch::from_bytes(f.fixed::<32>()?);
            let card_index = f.u16()?;
            let slot = f.u8()?;
            let identity = derive::derive_olm_identity(&m);
            let card_secret = derive::derive_card_secret(&m, card_index);
            let schedule = derive::derive_schedule_key(&m, card_index);
            Ok(vec![
                derive::olm_identity_public(&identity).to_vec(),
                card_secret.as_bytes().to_vec(),
                derive::derive_inbox_namespace(&card_secret).to_vec(),
                derive::derive_bundle_namespace(&card_secret).to_vec(),
                derive::derive_card_value(&card_secret, CardLabel::Deposit(slot)).to_vec(),
                derive::derive_card_value(&card_secret, CardLabel::BundleRead(slot)).to_vec(),
                derive::derive_card_value(&card_secret, CardLabel::BundleSeal).to_vec(),
                derive::derive_card_value(&card_secret, CardLabel::IntroOuter).to_vec(),
                derive::derive_inbox_read_secret(&m, card_index, slot).to_vec(),
                schedule.to_vec(),
                derive::publication_offset(&schedule).to_be_bytes().to_vec(),
            ])
        }
        kind::CARD_BUILD => {
            let seed = f.fixed::<32>()?;
            let m = MessagingBranch::from_bytes(f.fixed::<32>()?);
            let card_index = f.u16()?;
            let secret = derive::derive_card_secret(&m, card_index);
            let built = card::build(&seed, card_index, &secret);
            let bytes = built.encode();
            let reparsed = card::parse(&bytes)?;
            Ok(vec![
                bytes.to_vec(),
                built.link().into_bytes(),
                reparsed.encode().to_vec(),
                card::ghost1(&reparsed.identity_pk).into_bytes(),
            ])
        }
        kind::CARD_PARSE => {
            let parsed = card::parse(f.next()?)?;
            Ok(vec![
                parsed.encode().to_vec(),
                parsed.card_index.to_be_bytes().to_vec(),
            ])
        }
        kind::ACCOUNT => {
            let m = MessagingBranch::from_bytes(f.fixed::<32>()?);
            let fallback = f.next()?;
            let fallback = match fallback.len() {
                0 => None,
                32 => Some(fallback.try_into().map_err(|_| DmCode::NonCanonical)?),
                _ => return Err(DmCode::NonCanonical),
            };
            let secrets = AccountSecrets::from_branch(&m, fallback);
            let encoded = secrets.encode();
            let (curve, ed) = account::with_account(&secrets, |account| {
                let keys = account.identity_keys();
                Ok((
                    keys.curve25519.to_bytes().to_vec(),
                    keys.ed25519.as_bytes().to_vec(),
                ))
            })?;
            Ok(vec![encoded, secrets.identity_public().to_vec(), curve, ed])
        }
        kind::XWING => {
            let seed = KemSecret::from_bytes(f.fixed::<32>()?);
            let randomness = f.fixed::<{ pq::ENCAPS_RANDOMNESS_BYTES }>()?;
            let pair = pq::keygen(&seed)?;
            let (ciphertext, shared) = pq::encapsulate_with(&pair.public, &randomness)?;
            let opened = pq::decapsulate(&seed, &ciphertext)?;
            Ok(vec![
                pair.public.clone(),
                ciphertext,
                shared.as_bytes().to_vec(),
                opened.as_bytes().to_vec(),
            ])
        }
        kind::XWING_DECAPS => {
            let seed = KemSecret::from_bytes(f.fixed::<32>()?);
            let opened = pq::decapsulate(&seed, f.next()?)?;
            Ok(vec![opened.as_bytes().to_vec()])
        }
        kind::SEAL_PAIR | kind::SEAL_PROVISIONAL => {
            let key = pq_key(f.fixed::<32>()?);
            let namespace = f.fixed::<32>()?;
            let bucket = f.u32()? as usize;
            let oi_sender = f.fixed::<32>()?;
            let oi_recipient = f.fixed::<32>()?;
            let l1 = f.next()?;
            let salt = f.fixed::<{ seal::SALT_BYTES }>()?;
            let (blob, mode) = if case_kind == kind::SEAL_PAIR {
                let blob = seal::seal_pair_with(
                    &key,
                    &namespace,
                    bucket,
                    &oi_sender,
                    &oi_recipient,
                    l1,
                    &salt,
                )?;
                (blob, SealMode::Pair)
            } else {
                let blob = seal::seal_provisional_with(
                    &key,
                    &namespace,
                    bucket,
                    &oi_sender,
                    &oi_recipient,
                    l1,
                    &salt,
                )?;
                (blob, SealMode::Provisional)
            };
            let opened =
                seal::open_symmetric(&key, &namespace, mode, &oi_sender, &oi_recipient, &blob)?;
            Ok(vec![blob, opened])
        }
        kind::SEAL_BUNDLE => {
            let seed = f.fixed::<32>()?;
            let card_index = f.u16()?;
            let bundle_week = f.u64()?;
            let bundle_rank = f.u16()?;
            let gen_id = f.u32()?;
            let olm_identity = f.fixed::<32>()?;
            let fallback_key = f.fixed::<32>()?;
            let xwing_seed = KemSecret::from_bytes(f.fixed::<32>()?);
            let key = card_key(f.fixed::<32>()?);
            let namespace = f.fixed::<32>()?;
            let salt = f.fixed::<{ seal::SALT_BYTES }>()?;
            let xwing_public = pq::public_key(&xwing_seed)?;
            let plain = bundle::build(
                &seed,
                &bundle::BundleFields {
                    card_index,
                    bundle_week,
                    bundle_rank,
                    gen_id,
                    olm_identity: &olm_identity,
                    fallback_key: &fallback_key,
                    xwing_public: &xwing_public,
                },
            )?;
            let blob = seal::seal_bundle_with(&key, &namespace, &plain, &salt)?;
            let opened = seal::open_bundle(&key, &namespace, &blob, plain.len())?;
            Ok(vec![plain, blob, opened])
        }
        kind::OPEN_SYMMETRIC => {
            let key = pq_key(f.fixed::<32>()?);
            let namespace = f.fixed::<32>()?;
            let mode = match f.u8()? {
                0x01 => SealMode::Pair,
                0x04 => SealMode::Provisional,
                _ => return Err(DmCode::NonCanonical),
            };
            let oi_sender = f.fixed::<32>()?;
            let oi_recipient = f.fixed::<32>()?;
            let opened =
                seal::open_symmetric(&key, &namespace, mode, &oi_sender, &oi_recipient, f.next()?)?;
            Ok(vec![opened])
        }
        kind::SEAL_INTRO => {
            let outer_key = card_key(f.fixed::<32>()?);
            let namespace = f.fixed::<32>()?;
            let bucket = f.u32()? as usize;
            let gen_id = f.u32()?;
            let gen_seed = KemSecret::from_bytes(f.fixed::<32>()?);
            let recipient_oi = f.fixed::<32>()?;
            let recipient_identity_pk = f.fixed::<32>()?;
            let sender_seed = f.fixed::<32>()?;
            let sender_branch = MessagingBranch::from_bytes(f.fixed::<32>()?);
            let base_key = f.fixed::<32>()?;
            let binding_minute = f.u32()?;
            let reply_seed = ReplySeed::from_bytes(f.fixed::<32>()?);
            let l1 = f.next()?;
            let salt = f.fixed::<{ seal::SALT_BYTES }>()?;
            let randomness = f.fixed::<{ pq::ENCAPS_RANDOMNESS_BYTES }>()?;
            let gen_public = pq::public_key(&gen_seed)?;
            let sender_card = card::build(
                &sender_seed,
                0,
                &derive::derive_card_secret(&sender_branch, 0),
            )
            .encode();
            let sender_oi =
                derive::olm_identity_public(&derive::derive_olm_identity(&sender_branch));
            let context = IntroContext {
                namespace: &namespace,
                bucket,
                gen_id,
                gen_public: &gen_public,
                recipient_oi: &recipient_oi,
                recipient_identity_pk: &recipient_identity_pk,
            };
            let sender = IntroSender {
                identity_seed: &sender_seed,
                card: &sender_card,
                oi: &sender_oi,
                base_key: &base_key,
                binding_minute,
                reply_seed: &reply_seed,
            };
            let blob =
                seal::seal_intro_with(&outer_key, &context, &sender, l1, &salt, &randomness)?;
            let outer = seal::open_intro_outer(&outer_key, &namespace, &blob)?;
            let inner = seal::open_intro_layer(&gen_seed, &context, &outer)?;
            Ok(vec![
                blob,
                outer.gen_id.to_be_bytes().to_vec(),
                outer.ciphertext.clone(),
                inner.sender_card.to_vec(),
                inner.binding_minute.to_be_bytes().to_vec(),
                inner.binding_sig.to_vec(),
                inner.reply_seed.as_bytes().to_vec(),
                inner.l1.clone(),
            ])
        }
        kind::L0_DECODE => {
            let decoded = codec::decode(f.next()?)?;
            Ok(vec![decoded.encode()?])
        }
        kind::SAFETY => {
            let own = Party {
                identity_pk: f.fixed::<32>()?,
                olm_identity: f.fixed::<32>()?,
            };
            let peer = Party {
                identity_pk: f.fixed::<32>()?,
                olm_identity: f.fixed::<32>()?,
            };
            let number = safety::safety_number(&own, &peer);
            Ok(vec![number.display.into_bytes(), number.scannable.to_vec()])
        }
        kind::WRAP => {
            let key = StateKey::from_bytes(f.fixed::<32>()?);
            let name = wrap_name(f.u8()?)?;
            let binding = f.next()?;
            let plaintext = f.next()?;
            let nonce = f.fixed::<{ wrap::NONCE_BYTES }>()?;
            let envelope = wrap::wrap_with_nonce(&key, name, binding, plaintext, &nonce)?;
            let opened = wrap::unwrap(&key, name, binding, &envelope)?;
            Ok(vec![envelope, opened.to_vec()])
        }
        kind::OLM_DECRYPT => {
            let state = f.next()?;
            let l1 = f.next()?;
            let is_pre_key = f.u8()? == 1;
            let today = f.u32()?;
            let decrypted = session::decrypt(
                &[StoredSession {
                    slot: Slot::Current,
                    state,
                }],
                l1,
                is_pre_key,
                today,
            )?;
            Ok(vec![
                decrypted.plaintext,
                decrypted.state,
                vec![u8::from(decrypted.acknowledged)],
            ])
        }
        kind::OLM_ENCRYPT => {
            let state = f.next()?;
            let l0 = f.next()?;
            let today = f.u32()?;
            let encrypted = session::encrypt(state, l0, today)?;
            Ok(vec![
                encrypted.l1,
                vec![u8::from(encrypted.is_pre_key)],
                encrypted.state,
                vec![u8::from(encrypted.acknowledged)],
            ])
        }
        kind::OLM_PRUNE => {
            let state = f.next()?;
            let today = f.u32()?;
            let (pruned, removed) = session::session_prune(state, today)?;
            Ok(vec![pruned, (removed as u32).to_be_bytes().to_vec()])
        }
        kind::CONTROL => {
            use sha2::Digest;
            Ok(vec![sha2::Sha256::digest(f.next()?).to_vec()])
        }
        _ => Err(DmCode::NonCanonical),
    }
}

/// The JNI shim of [`run`]: `org.ghost.crypto.bridge.DmEquivalence.run(kind, input)`, whose Kotlin
/// declaration lives only in `:crypto-bridge`'s test and `androidTest` source sets (gate G-DM5).
/// `ghost-dm-host` invokes [`crate::export_equivalence_jni`]; no shipped library does.
#[cfg(feature = "jni-bridge")]
pub mod jni_entry {
    use jni::objects::{JByteArray, JClass};
    use jni::sys::{jboolean, jbyteArray, jint, jlong, JNI_FALSE, JNI_TRUE};
    use jni::JNIEnv;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    /// `DmEquivalence.run`: a panic is `INTERNAL`, a null input or an unconvertible one
    /// `NON_CANONICAL`, both as a one-byte answer like every other code.
    pub fn run<'local>(
        env: JNIEnv<'local>,
        _class: JClass<'local>,
        case_kind: jint,
        input: JByteArray<'local>,
    ) -> jbyteArray {
        crate::jni::quiet_panics();
        let reply = match (env.convert_byte_array(&input), u8::try_from(case_kind)) {
            (Ok(bytes), Ok(k)) => catch_unwind(AssertUnwindSafe(|| super::run(k, &bytes)))
                .unwrap_or_else(|_| vec![super::DmCode::Internal.as_u8()]),
            _ => vec![super::DmCode::NonCanonical.as_u8()],
        };
        match env.byte_array_from_slice(&reply) {
            Ok(array) => array.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// `DmEquivalence.bindingHooks`: MC-20 and KC5b's binding hooks of one DM context
    /// (`crate::binding::hooks`, design §22.37). False for a code out of range.
    pub fn binding_hooks(handle: jlong, omit: jint, perturb: jint) -> jboolean {
        let set = match (u8::try_from(omit), u8::try_from(perturb)) {
            (Ok(omit), Ok(perturb)) => crate::binding::hooks::set(handle, omit, perturb),
            _ => false,
        };
        if set {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }

    /// `DmEquivalence.stateWrapHook`: ME-24's hook of one DM context (`crate::wrap::hooks`, design
    /// §22.38) — its session states stored unwrapped, or wrapped again.
    pub fn state_wrap_hook(handle: jlong, unwrapped: jboolean) -> jboolean {
        crate::wrap::hooks::set(handle, unwrapped != JNI_FALSE);
        JNI_TRUE
    }

    /// `DmEquivalence.sidecarLogHook`: MC-30's sidecar-log hook of one DM context
    /// (`crate::olm::state::hooks`, design §22.38) — its sidecars kept as an insert-only log, or
    /// rebuilt as projections again.
    pub fn sidecar_log_hook(handle: jlong, on: jboolean) -> jboolean {
        crate::olm::state::hooks::set(handle, on != JNI_FALSE);
        JNI_TRUE
    }
}

/// Emits the **test-vectors entry points** of §22.8.10 point 6 in the invoking crate, exported by
/// the test libraries only (G-R6 checks they are there in them and nowhere else):
/// `Java_org_ghost_crypto_bridge_DmEquivalence_run` (slice S12), since §22.37
/// `Java_org_ghost_crypto_bridge_DmEquivalence_bindingHooks`, MC-20 and KC5b's switch, and since
/// §22.38 `Java_org_ghost_crypto_bridge_DmEquivalence_stateWrapHook`, ME-24's, and
/// `Java_org_ghost_crypto_bridge_DmEquivalence_sidecarLogHook`, MC-30's.
#[cfg(feature = "jni-bridge")]
#[macro_export]
macro_rules! export_equivalence_jni {
    () => {
        /// The equivalence-test entry point (design §15.9 item 7); test libraries only.
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_DmEquivalence_run<'local>(
            env: ::jni::JNIEnv<'local>,
            class: ::jni::objects::JClass<'local>,
            case_kind: ::jni::sys::jint,
            input: ::jni::objects::JByteArray<'local>,
        ) -> ::jni::sys::jbyteArray {
            $crate::equivalence::jni_entry::run(env, class, case_kind, input)
        }

        /// MC-20 and KC5b's binding hooks of one DM context (design §22.37); test libraries only.
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_DmEquivalence_bindingHooks<'local>(
            _env: ::jni::JNIEnv<'local>,
            _class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            omit: ::jni::sys::jint,
            perturb: ::jni::sys::jint,
        ) -> ::jni::sys::jboolean {
            $crate::equivalence::jni_entry::binding_hooks(handle, omit, perturb)
        }

        /// ME-24's state-wrap hook of one DM context (design §22.38); test libraries only.
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_DmEquivalence_stateWrapHook<'local>(
            _env: ::jni::JNIEnv<'local>,
            _class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            unwrapped: ::jni::sys::jboolean,
        ) -> ::jni::sys::jboolean {
            $crate::equivalence::jni_entry::state_wrap_hook(handle, unwrapped)
        }

        /// MC-30's sidecar-log hook of one DM context (design §22.38); test libraries only.
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_DmEquivalence_sidecarLogHook<'local>(
            _env: ::jni::JNIEnv<'local>,
            _class: ::jni::objects::JClass<'local>,
            handle: ::jni::sys::jlong,
            on: ::jni::sys::jboolean,
        ) -> ::jni::sys::jboolean {
            $crate::equivalence::jni_entry::sidecar_log_hook(handle, on)
        }
    };
}
