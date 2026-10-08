//! The vector-replay entry point of the JDK replay (design §5.2 rule (4), §12.2's Kotlin half;
//! slice S2b): a deterministic case runner over the crate's own derivations and codecs, so the JVM
//! tests replay `protocol/test-vectors/ch_*.txt` **through the host library** — the code the
//! shipped `libghost_client_net.so` links — byte for byte, for the values `MlsNative` cannot reach
//! on its own: a key given in clear (the vectors' `K_ep`, `G`, `JK`, invite seed), a fixed salt (a
//! shipped seal and invite draw theirs from the CSPRNG), the intermediate derivations `MlsNative`
//! never returns (`RB_g`, `DB_g`, the per-blob seal keys, the Argon2id output).
//!
//! **Test libraries only.** Compiled with the `test-vectors` feature, which only `ghost-dm-host`
//! enables; with `jni-bridge` it adds the one JNI symbol `Java_org_ghost_crypto_bridge_MlsVectors_run`
//! (Kotlin's declaration lives in `:crypto-bridge`'s `src/test`). G-M2 keeps the feature out of
//! every shipped graph; G-M6 refuses a shipped library that exports the symbol, and a test library
//! that exports anything else.
//!
//! **Wire.** The input is positional: `(u32_be(len) ‖ bytes)*`; the reply is `code(1)` followed by
//! the outputs the same way. A malformed input is `NON_CANONICAL`; a refusal of the code under test
//! is its own code.

use crate::derive::{
    self, committers_digest, derive_deposit_base, derive_deposit_secret, derive_epoch_recognition,
    derive_epoch_seal_key, derive_invite_password_key, derive_invite_seal_key,
    derive_invite_signing_key, derive_join_key, derive_join_recognition, derive_join_seal_key,
    derive_namespace, derive_open_invite_seal_key, derive_read_base, derive_read_secret,
    CredentialKind, DepositBase, EpochExport, GenerationSecret, InvitePassword, InviteSeed,
    JoinKey, OpenInviteSalt, PseudonymSeed, ReadBase, StateKey,
};
use crate::group::{ChannelHandle, KeyClass, MlsContext};
use crate::invite::{self, InviteFields};
use crate::kv::{Scope, WrappedRow, WrappedRows};
use crate::result::{Code, MlsError, MlsResult};
use crate::seal::{self, Order, SealKeyInput};
use zeroize::Zeroizing;

/// The case kinds (the Kotlin `MlsVectors` holds the same numbers).
pub mod kind {
    /// `[state_key, class(1), channel_id, key, epoch(u64)] → [envelope]`.
    pub const WRAP_KEY: u8 = 1;
    /// `[K_ep] → [R_ep]`.
    pub const DERIVE_EPOCH: u8 = 2;
    /// `[G, slot(1)] → [ns, RB, DB, JK, R_join, RS, DS, READ credential, its verifier, DEPOSIT
    /// credential, its verifier]`.
    pub const DERIVE_GENERATION: u8 = 3;
    /// `[K_ep, JK, salt(16), ns] → [epoch seal key, join seal key]`.
    pub const SEAL_KEYS: u8 = 4;
    /// `[invite_seed] → [invite_pk]`.
    pub const INVITE_KEY: u8 = 5;
    /// `[channel_id, committers (32 bytes each)] → [digest]`.
    pub const COMMITTERS_DIGEST: u8 = 6;
    /// `[salt(16), password] → [open seal key, Argon2id output, password seal key]`.
    pub const INVITE_SEAL: u8 = 7;
    /// `[m(u32), t(u32), p(u32), password, salt, secret, associated data] → [tag(32)]`.
    pub const ARGON2ID: u8 = 8;
    /// `[class(1), key, epoch(u64), ns, bucket(u32), mode(1), salt(16), order(16), body] → [blob]`.
    pub const SEAL: u8 = 9;
    /// `[kdf_code(1), password (empty: none), salt(16), size_class(1), handshake_ttl_code(1),
    /// channel_id, generation(u32), ns, RB, DB, JK, invite_id(16), invite_seed, committers_digest,
    /// expiry_day(u32), name] → [invite]`.
    pub const INVITE_BUILD: u8 = 10;
    /// `[invite] → [link text]`.
    pub const LINK: u8 = 11;
    /// `[handle(i64)] → —`: a panic inside the named `MlsNative` context, as a library panic during
    /// a call would raise it (the lifecycle test: the reply is `INTERNAL`, and the handle, its
    /// channels and `ctxClose` keep working). A closed handle is `CRYPTO_UNAVAILABLE`, no panic.
    pub const PANIC_IN_CONTEXT: u8 = 12;
    /// `[state_key, channel_id, pseudonym_seed, rows, day] → [proposal]`: a real MLS Proposal by
    /// the member (F-S4-6, MM-30's test entry; `MlsContext::test_proposal`). `rows` is one item,
    /// the concatenation of `(scope(1) ‖ u32be(key_len) ‖ key ‖ u32be(env_len) ‖ env)*`.
    pub const PROPOSAL: u8 = 13;
    /// `[state_key, channel_id, pseudonym_seed, not_before(u64), not_after(u64), rows, day] →
    /// [key_package, commit]`: a commit by the member adding a finite-lifetime (non-canonical)
    /// KeyPackage (MM-46 / SCN-CM's lifetime cases; `MlsContext::test_finite_lifetime_commit`).
    /// `rows` is encoded as in [`PROPOSAL`].
    pub const FINITE_KP_COMMIT: u8 = 14;
    /// `[state_key, channel_id, pseudonym_seed, wrong_identity(32), rows, day] → [commit]`: the
    /// member's own commit whose update-path leaf carries a mismatched credential (MM-31 /
    /// §19.14's NEW_SIGNER; `MlsContext::test_new_signer`). `rows` is encoded as in [`PROPOSAL`].
    pub const NEW_SIGNER_COMMIT: u8 = 15;
}

/// Decodes the `rows` item of [`kind::PROPOSAL`] and [`kind::FINITE_KP_COMMIT`]: the
/// concatenation of `(scope(1) ‖ u32be(key_len) ‖ key ‖ u32be(env_len) ‖ env)*`, the wrapped
/// `mls_kv`/global rows of §3.4 point 2.
fn rows_of(b: &[u8]) -> MlsResult<Vec<WrappedRow>> {
    let mut rest = b;
    let mut out = Vec::new();
    while !rest.is_empty() {
        let (&scope, tail) = rest.split_first().ok_or_else(nc)?;
        let (len, tail) = tail.split_at_checked(4).ok_or_else(nc)?;
        let klen = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
        let (key, tail) = tail.split_at_checked(klen).ok_or_else(nc)?;
        let (len, tail) = tail.split_at_checked(4).ok_or_else(nc)?;
        let elen = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
        let (env, tail) = tail.split_at_checked(elen).ok_or_else(nc)?;
        out.push(WrappedRow {
            scope: Scope::from_u8(scope).ok_or_else(nc)?,
            key: key.to_vec(),
            env: env.to_vec(),
        });
        rest = tail;
    }
    Ok(out)
}

fn nc() -> MlsError {
    MlsError::new(Code::NonCanonical)
}

/// The positional input.
struct Items<'a> {
    rest: &'a [u8],
}

impl<'a> Items<'a> {
    fn next(&mut self) -> MlsResult<&'a [u8]> {
        let (len, tail) = self.rest.split_at_checked(4).ok_or_else(nc)?;
        let len = usize::try_from(u32::from_be_bytes([len[0], len[1], len[2], len[3]]))
            .map_err(|_| nc())?;
        let (value, after) = tail.split_at_checked(len).ok_or_else(nc)?;
        self.rest = after;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> MlsResult<[u8; N]> {
        <[u8; N]>::try_from(self.next()?).map_err(|_| nc())
    }

    fn u8(&mut self) -> MlsResult<u8> {
        Ok(self.fixed::<1>()?[0])
    }

    fn u32(&mut self) -> MlsResult<u32> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> MlsResult<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn done(&self) -> MlsResult<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(nc())
        }
    }
}

fn reply(outputs: &[&[u8]]) -> Vec<u8> {
    let mut o = vec![Code::Ok.as_u8()];
    for v in outputs {
        o.extend_from_slice(&u32::try_from(v.len()).unwrap_or(u32::MAX).to_be_bytes());
        o.extend_from_slice(v);
    }
    o
}

/// Runs one case; the reply is `code(1) ‖ (u32_be(len) ‖ output)*`.
pub fn run(kind: u8, input: &[u8]) -> Vec<u8> {
    match run_case(kind, input) {
        Ok(out) => out,
        Err(e) => vec![e.code.as_u8()],
    }
}

fn run_case(case: u8, input: &[u8]) -> MlsResult<Vec<u8>> {
    let mut i = Items { rest: input };
    let out = match case {
        kind::WRAP_KEY => {
            let state_key = StateKey::from_bytes(i.fixed()?);
            let class = KeyClass::from_u8(i.u8()?).ok_or_else(nc)?;
            let channel_id: [u8; 32] = i.fixed()?;
            let key = Zeroizing::new(i.fixed::<32>()?);
            let epoch = i.u64()?;
            i.done()?;
            let ctx = MlsContext::open(state_key)?;
            let env = match class {
                KeyClass::Epoch => ctx.wrap_epoch_key(&channel_id, epoch, &key)?,
                other => ctx.wrap_key(other, &channel_id, &key)?,
            };
            reply(&[&env])
        }
        kind::DERIVE_EPOCH => {
            let k = EpochExport::from_bytes(i.fixed()?);
            i.done()?;
            reply(&[derive_epoch_recognition(&k).as_bytes()])
        }
        kind::DERIVE_GENERATION => {
            let g = GenerationSecret::from_bytes(i.fixed()?);
            let slot = i.u8()?;
            i.done()?;
            let ns = derive_namespace(&g);
            let (rb, db, jk) = (
                derive_read_base(&g),
                derive_deposit_base(&g),
                derive_join_key(&g),
            );
            let rs = derive_read_secret(&rb, slot);
            let ds = derive_deposit_secret(&db, slot);
            reply(&[
                &ns,
                rb.as_bytes(),
                db.as_bytes(),
                jk.as_bytes(),
                derive_join_recognition(&jk).as_bytes(),
                &rs,
                &ds,
                &derive::credential_v3(CredentialKind::Read, slot, &ns, &rs),
                &derive::credential_verifier(CredentialKind::Read, slot, &ns, &rs),
                &derive::credential_v3(CredentialKind::Deposit, slot, &ns, &ds),
                &derive::credential_verifier(CredentialKind::Deposit, slot, &ns, &ds),
            ])
        }
        kind::SEAL_KEYS => {
            let k = EpochExport::from_bytes(i.fixed()?);
            let jk = JoinKey::from_bytes(i.fixed()?);
            let salt: [u8; 16] = i.fixed()?;
            let ns: [u8; 32] = i.fixed()?;
            i.done()?;
            reply(&[
                derive_epoch_seal_key(&k, &salt, &ns).as_bytes(),
                derive_join_seal_key(&jk, &salt, &ns).as_bytes(),
            ])
        }
        kind::INVITE_KEY => {
            let seed = InviteSeed::from_bytes(i.fixed()?);
            i.done()?;
            reply(&[&derive_invite_signing_key(&seed).verifying_key().to_bytes()])
        }
        kind::COMMITTERS_DIGEST => {
            let channel_id: [u8; 32] = i.fixed()?;
            let list = i.next()?;
            i.done()?;
            let (keys, rest) = list.as_chunks::<32>();
            if !rest.is_empty() {
                return Err(nc());
            }
            reply(&[&committers_digest(&channel_id, keys).ok_or_else(nc)?])
        }
        kind::INVITE_SEAL => {
            let salt: [u8; 16] = i.fixed()?;
            let pw = InvitePassword::from_bytes(i.next()?.to_vec());
            i.done()?;
            let ikm = derive_invite_password_key(&pw, &salt, 1)?;
            reply(&[
                derive_open_invite_seal_key(&OpenInviteSalt::from_bytes(salt)).as_bytes(),
                ikm.as_bytes(),
                derive_invite_seal_key(&ikm, &salt, 1).as_bytes(),
            ])
        }
        kind::ARGON2ID => {
            let (m, t, p) = (i.u32()?, i.u32()?, i.u32()?);
            let (pw, salt, secret, ad) = (i.next()?, i.next()?, i.next()?, i.next()?);
            i.done()?;
            let params = argon2::ParamsBuilder::new()
                .m_cost(m)
                .t_cost(t)
                .p_cost(p)
                .data(argon2::AssociatedData::new(ad).map_err(|_| nc())?)
                .output_len(32)
                .build()
                .map_err(|_| nc())?;
            let a = argon2::Argon2::new_with_secret(
                secret,
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                params,
            )
            .map_err(|_| nc())?;
            let mut tag = Zeroizing::new([0u8; 32]);
            a.hash_password_into(pw, salt, tag.as_mut())
                .map_err(|_| nc())?;
            reply(&[tag.as_ref()])
        }
        kind::SEAL => {
            let class = KeyClass::from_u8(i.u8()?).ok_or_else(nc)?;
            let key: [u8; 32] = i.fixed()?;
            let epoch = i.u64()?;
            let ns: [u8; 32] = i.fixed()?;
            let bucket = usize::try_from(i.u32()?).map_err(|_| nc())?;
            let mode = i.u8()?;
            let salt: [u8; 16] = i.fixed()?;
            let order = Order::decode(&i.fixed::<16>()?);
            let body = i.next()?;
            i.done()?;
            let blob = match class {
                KeyClass::Epoch => {
                    let k = EpochExport::from_bytes(key);
                    seal::seal(
                        &SealKeyInput::Epoch { key: &k, epoch },
                        &ns,
                        bucket,
                        mode,
                        &order,
                        body,
                        salt,
                    )?
                }
                KeyClass::Join => {
                    let k = JoinKey::from_bytes(key);
                    seal::seal(
                        &SealKeyInput::Join(&k),
                        &ns,
                        bucket,
                        mode,
                        &order,
                        body,
                        salt,
                    )?
                }
                _ => return Err(nc()),
            };
            reply(&[&blob])
        }
        kind::INVITE_BUILD => {
            let kdf_code = i.u8()?;
            let pw = i.next()?;
            let password = (!pw.is_empty()).then(|| InvitePassword::from_bytes(pw.to_vec()));
            let salt: [u8; 16] = i.fixed()?;
            let fields = InviteFields {
                suite: invite::SUITE,
                size_class: i.u8()?,
                handshake_ttl_code: i.u8()?,
                channel_id: i.fixed()?,
                generation: i.u32()?,
                ns: i.fixed()?,
                read_base: ReadBase::from_bytes(i.fixed()?),
                deposit_base: DepositBase::from_bytes(i.fixed()?),
                join_key: JoinKey::from_bytes(i.fixed()?),
                invite_id: i.fixed()?,
                invite_seed: InviteSeed::from_bytes(i.fixed()?),
                committers_digest: i.fixed()?,
                expiry_day: i.u32()?,
                name: i.next()?.to_vec(),
            };
            i.done()?;
            let bytes = invite::build_v2(&fields, kdf_code, password.as_ref(), salt)?;
            reply(&[&bytes])
        }
        kind::LINK => {
            let bytes = i.next()?;
            i.done()?;
            reply(&[invite::to_link(bytes).as_bytes()])
        }
        #[cfg(feature = "jni-bridge")]
        kind::PANIC_IN_CONTEXT => {
            let handle = i64::from_be_bytes(i.fixed()?);
            i.done()?;
            crate::jni::panic_inside_context(handle)?;
            reply(&[])
        }
        kind::PROPOSAL => {
            let state_key = StateKey::from_bytes(i.fixed()?);
            let channel_id: [u8; 32] = i.fixed()?;
            let seed = PseudonymSeed::from_bytes(i.fixed()?);
            let rows = rows_of(i.next()?)?;
            let day = i.u32()?;
            i.done()?;
            let ctx = MlsContext::open(state_key)?;
            let ch = ChannelHandle::open(channel_id, &seed);
            let proposal = ctx.test_proposal(&ch, &WrappedRows(&rows), day)?;
            reply(&[&proposal])
        }
        kind::FINITE_KP_COMMIT => {
            let state_key = StateKey::from_bytes(i.fixed()?);
            let channel_id: [u8; 32] = i.fixed()?;
            let seed = PseudonymSeed::from_bytes(i.fixed()?);
            let not_before = i.u64()?;
            let not_after = i.u64()?;
            let rows = rows_of(i.next()?)?;
            let day = i.u32()?;
            i.done()?;
            let ctx = MlsContext::open(state_key)?;
            let ch = ChannelHandle::open(channel_id, &seed);
            let (kp, commit) = ctx.test_finite_lifetime_commit(
                &ch,
                &WrappedRows(&rows),
                day,
                not_before,
                not_after,
            )?;
            reply(&[&kp, &commit])
        }
        kind::NEW_SIGNER_COMMIT => {
            let state_key = StateKey::from_bytes(i.fixed()?);
            let channel_id: [u8; 32] = i.fixed()?;
            let seed = PseudonymSeed::from_bytes(i.fixed()?);
            let wrong_identity: [u8; 32] = i.fixed()?;
            let rows = rows_of(i.next()?)?;
            let day = i.u32()?;
            i.done()?;
            let ctx = MlsContext::open(state_key)?;
            let ch = ChannelHandle::open(channel_id, &seed);
            let commit = ctx.test_new_signer(&ch, &WrappedRows(&rows), day, wrong_identity)?;
            reply(&[&commit])
        }
        _ => return Err(nc()),
    };
    Ok(out)
}

/// The JNI shim of [`run`]: `org.ghost.crypto.bridge.MlsVectors.run(kind, input)`, whose Kotlin
/// declaration lives only in `:crypto-bridge`'s `src/test` (G-DM5, G-M6). `ghost-dm-host` invokes
/// [`crate::export_vectors_jni`]; no shipped library does.
#[cfg(feature = "jni-bridge")]
pub mod jni_entry {
    use jni::objects::{JByteArray, JClass};
    use jni::sys::{jbyteArray, jint};
    use jni::JNIEnv;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    /// `MlsVectors.run`: a panic is `INTERNAL`, a null or unconvertible input `NON_CANONICAL`,
    /// both as a one-byte reply like every other code.
    pub fn run<'l>(
        env: JNIEnv<'l>,
        _class: JClass<'l>,
        case_kind: jint,
        input: JByteArray<'l>,
    ) -> jbyteArray {
        crate::jni::quiet_panics();
        let converted = if input.is_null() {
            None
        } else {
            env.convert_byte_array(&input).ok()
        };
        let reply = match (converted, u8::try_from(case_kind)) {
            (Some(bytes), Ok(k)) => catch_unwind(AssertUnwindSafe(|| super::run(k, &bytes)))
                .unwrap_or_else(|_| vec![super::Code::Internal.as_u8()]),
            _ => vec![super::Code::NonCanonical.as_u8()],
        };
        match env.byte_array_from_slice(&reply) {
            Ok(array) => array.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

/// Emits the **test-vectors entry point** in the invoking crate, exported by the test library
/// only (G-M6 checks it is there and nowhere else): `Java_org_ghost_crypto_bridge_MlsVectors_run`.
#[cfg(feature = "jni-bridge")]
#[macro_export]
macro_rules! export_vectors_jni {
    () => {
        /// The vector-replay entry point (design §12.2); test libraries only.
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsVectors_run<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            case_kind: ::jni::sys::jint,
            input: ::jni::objects::JByteArray<'l>,
        ) -> ::jni::sys::jbyteArray {
            $crate::testvec::jni_entry::run(env, class, case_kind, input)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(items: &[&[u8]]) -> Vec<u8> {
        let mut o = Vec::new();
        for v in items {
            o.extend_from_slice(&(v.len() as u32).to_be_bytes());
            o.extend_from_slice(v);
        }
        o
    }

    #[test]
    fn a_case_replies_positionally_and_refuses_malformed_input() {
        let k = [0x11u8; 32];
        let out = run(kind::DERIVE_EPOCH, &input(&[&k]));
        assert_eq!(out[0], 0);
        let want = derive_epoch_recognition(&EpochExport::from_bytes(k));
        assert_eq!(&out[5..], want.as_bytes());
        assert_eq!(run(kind::DERIVE_EPOCH, &input(&[&k[..31]])), vec![13]);
        assert_eq!(run(kind::DERIVE_EPOCH, &input(&[&k, &k])), vec![13]);
        assert_eq!(run(0x7f, &[]), vec![13]);
    }
}
