//! The PQ-C root vectors of `protocol/test-vectors/dm_derive.txt` `[pq_root]` (design §9.4,
//! slice S13), replayed by implementations that are **not** the one that wrote them.
//!
//! `vectors.rs` writes the section with `ghost_client_dm::pqroot` and compares the file byte for
//! byte, which proves the file is what the crate computes — not that the crate computes §9.4. This
//! test closes that gap from three sides:
//!
//!  1. the X-Wing half through RustCrypto `x-wing 0.1.0` (the dev-only differential oracle of §9.2,
//!     an independent ML-KEM-768 and X25519): the recorded key, ciphertext and `ss` must be what
//!     *it* derives from the recorded seed and randomness;
//!  2. the derivation from the formula itself, with `sha2` and `hkdf` called directly — the label,
//!     the order of the salt inputs, the order of the ikm halves;
//!  3. GHOST's opener on the recorded TLV bytes, which must land on the recorded root.
//!
//! The JDK half of the same replay (salt and HKDF from `ss`, with `javax.crypto`) is
//! `PqRootVectorTest` in `:crypto-bridge`, the §15.2 cross-check seam for everything but ML-KEM.

use ghost_client_dm::codec::{self, SealRootPq};
use ghost_client_dm::derive::KemSecret;
use ghost_client_dm::pq;
use ghost_client_dm::pqroot::{self, PqRootParties};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;

fn section(name: &str) -> HashMap<String, String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("protocol")
        .join("test-vectors")
        .join("dm_derive.txt");
    let text = std::fs::read_to_string(&path).expect("dm_derive.txt");
    let mut out = HashMap::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with('[') {
            inside = line == format!("[{name}]");
            continue;
        }
        if !inside || line.starts_with('#') || line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once(" = ").expect("key = value");
        out.insert(key.to_string(), value.to_string());
    }
    assert!(!out.is_empty(), "no [{name}] section in dm_derive.txt");
    out
}

fn hex_of(values: &HashMap<String, String>, key: &str) -> Vec<u8> {
    hex::decode(values.get(key).unwrap_or_else(|| panic!("{key} missing"))).expect("hex")
}

fn fixed<const N: usize>(values: &HashMap<String, String>, key: &str) -> [u8; N] {
    hex_of(values, key)
        .try_into()
        .unwrap_or_else(|_| panic!("{key} is not {N} bytes"))
}

#[test]
fn the_recorded_kem_half_is_what_an_independent_x_wing_derives() {
    use x_wing::{Decapsulate, Decapsulator, KeyExport};

    let v = section("pq_root");
    let seed: [u8; 32] = fixed(&v, "peer_xwing_seed");
    let randomness: [u8; 64] = fixed(&v, "kem_randomness");
    let other = x_wing::DecapsulationKey::from(seed);
    assert_eq!(
        other.encapsulation_key().to_bytes().as_slice(),
        hex_of(&v, "peer_xwing_pk").as_slice(),
        "the recorded public key is the seed's under RustCrypto x-wing"
    );
    let (ct, ss) = other
        .encapsulation_key()
        .encapsulate_deterministic(&randomness.into());
    assert_eq!(ct.as_slice(), hex_of(&v, "xwing_ct").as_slice());
    assert_eq!(ss.as_slice(), hex_of(&v, "ss").as_slice());
    let recorded_ct = x_wing::Ciphertext::try_from(hex_of(&v, "xwing_ct").as_slice())
        .expect("a 1 120-byte ciphertext");
    assert_eq!(
        other.decapsulate(&recorded_ct).as_slice(),
        hex_of(&v, "ss").as_slice(),
        "and it decapsulates the recorded ciphertext to the recorded secret"
    );
}

#[test]
fn the_recorded_root_is_the_formula_of_section_9_4() {
    let v = section("pq_root");
    assert_eq!(v["pq_root_label"], "ghost/v1/dm/pq-root");
    let gen_id: u32 = v["peer_gen_id"].parse().expect("u32");
    let mut salt_input = Vec::new();
    salt_input.extend_from_slice(b"ghost/v1/dm/pq-root");
    salt_input.extend_from_slice(&hex_of(&v, "oi_offerer"));
    salt_input.extend_from_slice(&hex_of(&v, "oi_target"));
    salt_input.extend_from_slice(&gen_id.to_be_bytes());
    salt_input.extend_from_slice(&hex_of(&v, "peer_xwing_pk"));
    salt_input.extend_from_slice(&hex_of(&v, "xwing_ct"));
    let salt = Sha256::digest(&salt_input);
    assert_eq!(salt.as_slice(), hex_of(&v, "salt").as_slice());

    let mut ikm = hex_of(&v, "root_rand");
    ikm.extend_from_slice(&hex_of(&v, "ss"));
    let mut root = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm)
        .expand(b"ghost/v1/dm/pq-root", &mut root)
        .expect("L = 32");
    assert_eq!(root.as_slice(), hex_of(&v, "pq_root").as_slice());
    assert_eq!(
        root.as_slice(),
        hex_of(&v, "pq_root_decapsulated").as_slice()
    );

    // The base-week key of the pair ratchet over the PQ root (§6.3), the same HKDF as a classical
    // root's: nothing downstream of the root knows which form it came in.
    let mut info = b"ghost/v1/dm/pair-epoch".to_vec();
    info.extend_from_slice(&2873u64.to_be_bytes());
    let mut week = [0u8; 32];
    Hkdf::<Sha256>::new(None, &root)
        .expand(&info, &mut week)
        .expect("L = 32");
    assert_eq!(week.as_slice(), hex_of(&v, "week_key_2873").as_slice());
}

#[test]
fn the_recorded_tlv_opens_to_the_recorded_root_and_its_layout_is_section_7_1() {
    let v = section("pq_root");
    let tlv_bytes = hex_of(&v, "seal_root_pq");
    assert_eq!(tlv_bytes.len(), codec::SEAL_ROOT_PQ_BYTES);
    // root_rand(32) || base_week(8) || root_gen(2) || peer_gen_id(4) || xwing_ct(1120)
    assert_eq!(&tlv_bytes[..32], hex_of(&v, "root_rand").as_slice());
    assert_eq!(&tlv_bytes[32..40], &2873u64.to_be_bytes());
    assert_eq!(&tlv_bytes[40..42], &9u16.to_be_bytes());
    let gen_id: u32 = v["peer_gen_id"].parse().expect("u32");
    assert_eq!(&tlv_bytes[42..46], &gen_id.to_be_bytes());
    assert_eq!(&tlv_bytes[46..], hex_of(&v, "xwing_ct").as_slice());

    let tlv = SealRootPq::decode(&tlv_bytes).expect("decode");
    let seed = KemSecret::from_bytes(fixed(&v, "peer_xwing_seed"));
    let offerer: [u8; 32] = fixed(&v, "oi_offerer");
    let target: [u8; 32] = fixed(&v, "oi_target");
    let root = pqroot::open(
        &tlv,
        gen_id,
        &seed,
        PqRootParties {
            oi_offerer: &offerer,
            oi_target: &target,
        },
    )
    .expect("open");
    assert_eq!(root.as_bytes().as_slice(), hex_of(&v, "pq_root").as_slice());
    let swapped = pqroot::open(
        &tlv,
        gen_id,
        &seed,
        PqRootParties {
            oi_offerer: &target,
            oi_target: &offerer,
        },
    )
    .expect("open");
    assert_eq!(
        swapped.as_bytes().as_slice(),
        hex_of(&v, "pq_root_roles_swapped").as_slice()
    );
    // The recorded key is the seed's under GHOST's own wrapper as well.
    assert_eq!(
        pq::public_key(&seed).expect("keygen"),
        hex_of(&v, "peer_xwing_pk")
    );
}
