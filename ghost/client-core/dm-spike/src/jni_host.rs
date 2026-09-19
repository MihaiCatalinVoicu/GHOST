//! V-5: the host-build shape of design §2.3 (`ghost-dm-host`, a cdylib with JNI exports) for
//! `org.ghost.dmspike.DmHostProbe` in `jvm/`. Byte arrays in, `code(1) ‖ payload` out; every entry
//! point runs under `catch_unwind`, like `ghost-client-net`'s bridge.

use crate::codes::Code;
use crate::derive;
use crate::msc3814::DehydratedSecrets;
use crate::olm::{random_bytes, v11 as olm, x25519_public};
use crate::xwing;
use jni::objects::{JByteArray, JClass};
use jni::sys::jbyteArray;
use jni::JNIEnv;
use std::panic::{catch_unwind, AssertUnwindSafe};

const OK: u8 = 0;
const INTERNAL: u8 = 0xff;

fn code_byte(code: Code) -> u8 {
    match code {
        Code::MissingKey => 1,
        Code::IdentityMismatch => 2,
        Code::InvalidKey => 3,
        Code::Undecryptable => 4,
        Code::DuplicateOrLost => 5,
        Code::GapTooBig => 6,
        Code::InvalidSession => 7,
        Code::StateCorrupt => 8,
        Code::NotOpen => 9,
    }
}

fn respond(
    env: &mut JNIEnv,
    input: &JByteArray,
    f: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, Code>,
) -> jbyteArray {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let bytes = env
            .convert_byte_array(input)
            .map_err(|_| Code::StateCorrupt)?;
        f(bytes)
    }));
    let mut out = match outcome {
        Ok(Ok(payload)) => {
            let mut out = vec![OK];
            out.extend_from_slice(&payload);
            out
        }
        Ok(Err(code)) => vec![code_byte(code)],
        Err(_) => vec![INTERNAL],
    };
    match env.byte_array_from_slice(&out) {
        Ok(array) => array.into_raw(),
        Err(_) => {
            out.clear();
            std::ptr::null_mut()
        }
    }
}

/// `olmRoundTrip(messagingBranch32)`: a seed-derived Olm identity receives a first message from a
/// throwaway sender and answers it; returns the Olm identity key ‖ the decrypted reply.
#[no_mangle]
pub extern "system" fn Java_org_ghost_dmspike_DmHostProbe_olmRoundTrip(
    mut env: JNIEnv,
    _class: JClass,
    messaging_branch: JByteArray,
) -> jbyteArray {
    respond(&mut env, &messaging_branch, |m| {
        let m: [u8; 32] = m.as_slice().try_into().map_err(|_| Code::StateCorrupt)?;
        let ids = derive::olm_identity(&m);
        let fallback: [u8; 32] = random_bytes();
        let me = DehydratedSecrets {
            curve25519: ids.identity,
            ed25519_seed: ids.account_signing_seed,
            fallback: Some(fallback),
        };
        let peer = DehydratedSecrets {
            curve25519: random_bytes(),
            ed25519_seed: random_bytes(),
            fallback: None,
        };
        let my_identity = x25519_public(&ids.identity);
        let (peer_state, _) =
            olm::session_outbound(&peer, &my_identity, &x25519_public(&fallback))?;
        let first = olm::encrypt(&peer_state, b"hello from the peer")?;
        let inbound = olm::session_inbound(&me, &x25519_public(&peer.curve25519), &first.l1)?;
        let reply = olm::encrypt(&inbound.pickle, b"hello from the JVM host build")?;
        let done = olm::decrypt(&first.pickle, &reply.l1, reply.is_prekey)?;
        let mut out = my_identity.to_vec();
        out.extend_from_slice(&done.plaintext);
        Ok(out)
    })
}

/// `xwingRoundTrip(seed32)`: X-Wing public key ‖ equal-secret flag after encaps and decaps.
#[no_mangle]
pub extern "system" fn Java_org_ghost_dmspike_DmHostProbe_xwingRoundTrip(
    mut env: JNIEnv,
    _class: JClass,
    seed: JByteArray,
) -> jbyteArray {
    respond(&mut env, &seed, |seed| {
        let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| Code::StateCorrupt)?;
        let public = xwing::public_key(&seed)?;
        let (ct, ss) = xwing::encapsulate(&public)?;
        let opened = xwing::decapsulate(&seed, &ct)?;
        let mut out = public;
        out.push(u8::from(opened == ss));
        Ok(out)
    })
}

/// `panicProbe(any)`: a Rust panic becomes the `INTERNAL` code, not a JVM abort.
#[no_mangle]
pub extern "system" fn Java_org_ghost_dmspike_DmHostProbe_panicProbe(
    mut env: JNIEnv,
    _class: JClass,
    input: JByteArray,
) -> jbyteArray {
    respond(&mut env, &input, |bytes| {
        let short: &[u8] = &bytes;
        let _ = libcrux_kem::PublicKey::decode(libcrux_kem::Algorithm::XWingKemDraft06, short);
        Ok(Vec::new())
    })
}
