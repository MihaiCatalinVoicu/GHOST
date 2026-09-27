//! Writes the committed seed corpora of the `dm-fuzz` targets (`corpus-seeds/<target>/`) from the
//! committed DM test vectors (`protocol/test-vectors/dm_*.txt`) and the golden Olm transcript
//! (`client-core/dm/tests/golden/vodozemac-<pin>/olm-session.txt`). Every seed is a target's mode
//! byte followed by that mode's input. The vectors hold no PreKey message (its creation draws
//! randomness), so one is made here from vector keys with the crate's own session API; it differs
//! from run to run and is committed as written.
//!
//! Usage (from this directory): `cargo run --release --example seeds -- <ghost dir> <out dir>`.

use ghost_client_dm::derive::OlmSecret;
use ghost_client_dm::olm::session;
use ghost_client_dm::{codec, revocation};
use std::collections::HashMap;
use std::path::Path;

type Vectors = HashMap<(String, String), String>;

fn read(path: &Path, into: &mut Vectors) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut section = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].to_string();
        } else if let Some((key, value)) = line.split_once(" = ") {
            into.insert((section.clone(), key.to_string()), value.to_string());
        }
    }
}

fn hex(v: &Vectors, section: &str, key: &str) -> Vec<u8> {
    let s = v
        .get(&(section.to_string(), key.to_string()))
        .unwrap_or_else(|| panic!("vector [{section}] {key} missing"));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn text(v: &Vectors, section: &str, key: &str) -> Vec<u8> {
    v[&(section.to_string(), key.to_string())]
        .as_bytes()
        .to_vec()
}

fn arr<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("vector length")
}

fn write(out: &Path, target: &str, name: &str, parts: &[&[u8]]) {
    let dir = out.join(target);
    std::fs::create_dir_all(&dir).expect("corpus directory");
    std::fs::write(dir.join(name), parts.concat()).expect("seed file");
}

fn symmetric_body(l1: &[u8]) -> Vec<u8> {
    let mut body = vec![0x01];
    body.extend_from_slice(&(l1.len() as u32).to_be_bytes());
    body.extend_from_slice(l1);
    body
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let ghost = Path::new(&args[1]);
    let out = Path::new(&args[2]);
    let mut v = Vectors::new();
    for name in ["dm_bundle", "dm_content", "dm_derive", "dm_seal"] {
        read(
            &ghost.join(format!("protocol/test-vectors/{name}.txt")),
            &mut v,
        );
    }
    let mut golden = Vectors::new();
    read(
        &ghost.join("client-core/dm/tests/golden/vodozemac-0.11.0/olm-session.txt"),
        &mut golden,
    );

    let card = hex(&v, "card", "card");
    let link = text(&v, "card", "card_link");
    let identity_seed = hex(&v, "bundle", "identity_seed");
    let card_secret = hex(&v, "seed_values", "card_secret");
    let bundle_plain = hex(&v, "bundle", "bundle_plain");
    let xwing_pk = hex(&v, "pq_root", "peer_xwing_pk");
    assert_eq!(bundle_plain.len(), 1393);
    let xwing_ct = hex(&v, "pq_root", "xwing_ct");
    let seal_root_pq = hex(&v, "pq_root", "seal_root_pq");
    let olm_identity = hex(&v, "bundle", "olm_identity");
    let fallback_key = hex(&v, "bundle", "fallback_key");
    let sender_card = hex(&v, "intro_common", "sender_card");
    let normal_l1 = hex(&golden, "", "held_for_responder.0.l1");
    let reply_l1 = hex(&golden, "", "held_for_initiator.0.l1");

    // A PreKey message from vector keys: the derive vectors' Olm identity toward the bundle
    // vector's identity and fallback key, carrying the plain-text L0 vector.
    let outbound = session::session_outbound(
        &OlmSecret::from_bytes(arr(&hex(&v, "olm_identity", "olm_identity_secret"))),
        &OlmSecret::from_bytes(arr(&hex(&v, "olm_identity", "olm_account_signing_seed"))),
        &arr(&olm_identity),
        &arr(&fallback_key),
        1000,
    )
    .expect("an outbound session to the bundle vector's keys");
    let encrypted = session::encrypt(&outbound.state, &hex(&v, "text_plain", "l0"), 1000)
        .expect("the first message of a session");
    assert!(encrypted.is_pre_key);
    let prekey_l1 = encrypted.l1;

    // card: raw, link and z-base-32, re-signed.
    write(out, "card", "raw-card", &[&[0], &card]);
    write(out, "card", "link", &[&[1, 131], &link]);
    write(out, "card", "zbase32", &[&[1, 131], &link[16..]]);
    write(
        out,
        "card",
        "resigned",
        &[&[2], &identity_seed, &[0, 0], &card_secret],
    );

    // bundle: raw plaintext, re-signed fields, sealed body, raw blob.
    // The re-signed mode's fields are the plaintext's own, in its order (card_index, week, rank,
    // gen_id, Olm identity, fallback key, X-Wing key): bytes 1 .. 1 + 1296 of the bundle vector.
    write(out, "bundle", "raw-plain", &[&[0], &bundle_plain]);
    write(
        out,
        "bundle",
        "resigned",
        &[&[1], &identity_seed, &bundle_plain[1..1 + 1296]],
    );
    write(out, "bundle", "sealed", &[&[2, 0x03], &bundle_plain]);
    write(
        out,
        "bundle",
        "raw-blob",
        &[&[3], &hex(&v, "pair_4096", "blob")],
    );

    // intro_inner: the inner plaintext, the whole envelope, an attacker ciphertext, re-signed.
    let inner: Vec<u8> = [
        &[0x02][..],
        &sender_card,
        &1000u32.to_be_bytes(),
        &[0u8; 64],
        &[0x31u8; 32],
        &(prekey_l1.len() as u32).to_be_bytes(),
        &prekey_l1,
    ]
    .concat();
    write(out, "intro_inner", "inner-4096", &[&[0x00], &inner]);
    write(
        out,
        "intro_inner",
        "envelope-4096",
        &[&[0x01], &7u32.to_be_bytes(), &inner],
    );
    write(
        out,
        "intro_inner",
        "attacker-ciphertext",
        &[&[0x02], &xwing_ct, &[0u8; 64]],
    );
    write(
        out,
        "intro_inner",
        "resigned-prekey",
        &[&[0x03], &1000u32.to_be_bytes(), &[0x31u8; 32], &prekey_l1],
    );

    // l0: every L0 vector.
    let mut ext = Vec::new();
    for section in [
        "text_plain",
        "text_quoted",
        "timer_set",
        "reaction",
        "control_seal_root",
        "control_seal_root_pq",
        "text_pq_key",
    ] {
        let l0 = hex(&v, section, "l0");
        let content = codec::decode(&l0).expect("an L0 vector decodes");
        for tlv in &content.ext {
            ext.push((tlv.tlv_type, tlv.value.clone()));
        }
        write(out, "l0", section, &[&l0]);
    }

    // tlvs: each value kind, raw and re-signed revocation, and a control L0's TLV list.
    let root = ext
        .iter()
        .find(|(t, _)| *t == codec::TLV_SEAL_ROOT)
        .expect("a SEAL_ROOT vector");
    write(out, "tlvs", "seal-root", &[&[0], &root.1]);
    write(out, "tlvs", "seal-root-pq", &[&[1], &seal_root_pq]);
    write(
        out,
        "tlvs",
        "pq-key",
        &[&[2], &7u32.to_be_bytes(), &[0u8; 8], &xwing_pk],
    );
    let certificate = revocation::issue(&arr(&identity_seed), 1000, 1).expect("a revocation");
    write(out, "tlvs", "revocation", &[&[3], &certificate]);
    write(
        out,
        "tlvs",
        "revocation-resigned",
        &[&[4], &identity_seed, &1000u32.to_be_bytes(), &[1]],
    );
    let mut list = Vec::new();
    for (tlv_type, value) in ext
        .iter()
        .filter(|(t, _)| *t == codec::TLV_SEAL_ROOT || *t == codec::TLV_SESSION_RESET)
    {
        list.extend_from_slice(&tlv_type.to_be_bytes());
        list.extend_from_slice(&(value.len() as u16).to_be_bytes());
        list.extend_from_slice(value);
    }
    write(out, "tlvs", "ext-list", &[&[5], &list]);

    // olm_message: normal and PreKey messages, raw and inside pair and provisional envelopes.
    write(out, "olm_message", "normal", &[&[0], &normal_l1]);
    write(out, "olm_message", "normal-reply", &[&[0], &reply_l1]);
    write(out, "olm_message", "prekey", &[&[1], &prekey_l1]);
    write(
        out,
        "olm_message",
        "pair-envelope",
        &[&[2, 0x01], &symmetric_body(&normal_l1)],
    );
    write(
        out,
        "olm_message",
        "provisional-envelope",
        &[&[3, 0x04], &symmetric_body(&prekey_l1)],
    );
}
