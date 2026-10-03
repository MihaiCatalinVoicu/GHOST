//! An independent replay of `protocol/test-vectors/ch_*.txt` (design §5.2 rule (4), §12.2): a
//! second implementation of the channel formats written from the design text and RFC 9420 alone,
//! **sharing no code with `ghost-client-mls`** — only the primitive crates (HKDF, HMAC, SHA-256,
//! ChaCha20-Poly1305, Ed25519, Argon2id). Every derivation is recomputed, every seal rebuilt and
//! opened, every content decoded and re-encoded under the canonical rules, every invite rebuilt,
//! and the sample KeyPackage parsed field by field as RFC 9420 §10 lays it out, its two signatures
//! verified (§5.1.2 SignWithLabel) and its reference recomputed (§5.2). The JDK replay is slice S2b.

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type Sections = BTreeMap<String, BTreeMap<String, String>>;

fn load(name: &str) -> Sections {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/test-vectors")
        .join(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("{} missing", path.display()));
    let mut out: Sections = BTreeMap::new();
    let mut section = String::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = s.to_string();
        } else {
            let (k, v) = line
                .split_once(" = ")
                .unwrap_or_else(|| panic!("{name}: bad line {line}"));
            out.entry(section.clone())
                .or_default()
                .insert(k.to_string(), v.to_string());
        }
    }
    out
}

fn h(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    hex::decode(s).unwrap_or_else(|_| panic!("not hex: {s}"))
}

fn a32(s: &str) -> [u8; 32] {
    h(s).try_into().unwrap()
}

fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut o)
        .unwrap();
    o
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

// ---- ch_derive ------------------------------------------------------------------------------

#[test]
fn replay_ch_derive() {
    let v = load("ch_derive.txt");
    let e = &v["epoch"];
    let k_ep = h(&e["k_ep"]);
    assert_eq!(
        hkdf(&k_ep, &[], b"ghost/v1/ch-recognition").to_vec(),
        h(&e["r_ep"])
    );

    let g = &v["generation"];
    let gs = h(&g["g"]);
    let ns = hkdf(&gs, &[], b"ghost/v1/ch/ns");
    let rb = hkdf(&gs, &[], b"ghost/v1/ch/read-base");
    let db = hkdf(&gs, &[], b"ghost/v1/ch/deposit-base");
    let jk = hkdf(&gs, &[], b"ghost/v1/ch/join-key");
    assert_eq!(ns.to_vec(), h(&g["ns"]));
    assert_eq!(rb.to_vec(), h(&g["read_base"]));
    assert_eq!(db.to_vec(), h(&g["deposit_base"]));
    assert_eq!(jk.to_vec(), h(&g["join_key"]));
    assert_eq!(
        hkdf(&jk, &[], b"ghost/v1/ch-recognition").to_vec(),
        h(&g["r_join"])
    );
    for s in [0u8, 7] {
        let rs = hkdf(&rb, &[], &cat(&[b"ghost/v1/ch/read", &[s]]));
        let ds = hkdf(&db, &[], &cat(&[b"ghost/v1/ch/deposit", &[s]]));
        assert_eq!(rs.to_vec(), h(&g[&format!("read_secret_slot_{s}")]));
        assert_eq!(ds.to_vec(), h(&g[&format!("deposit_secret_slot_{s}")]));
        // Credential v3 and verifiers (F9 §4.3).
        let rc = cat(&[&[3, 0x01, s], &ns, &rs]);
        let dc = cat(&[&[3, 0x03, s], &ns, &ds]);
        assert_eq!(rc, h(&g[&format!("read_credential_slot_{s}")]));
        assert_eq!(dc, h(&g[&format!("deposit_credential_slot_{s}")]));
        let rv = Sha256::digest(cat(&[b"ghost/v1/read-verifier", &[s], &ns, &rs]));
        let dv = Sha256::digest(cat(&[b"ghost/v1/deposit-verifier", &[s], &ns, &ds]));
        assert_eq!(rv.to_vec(), h(&g[&format!("read_verifier_slot_{s}")]));
        assert_eq!(dv.to_vec(), h(&g[&format!("deposit_verifier_slot_{s}")]));
    }

    let sk = &v["seal_keys"];
    let salt = h(&sk["salt"]);
    let sns = h(&sk["ns"]);
    assert_eq!(
        hkdf(&k_ep, &salt, &cat(&[b"ghost/v1/ch-seal", &sns])).to_vec(),
        h(&sk["epoch_seal_key"])
    );
    assert_eq!(
        hkdf(&jk, &salt, &cat(&[b"ghost/v1/ch-seal", &sns])).to_vec(),
        h(&sk["join_seal_key"])
    );

    let p = &v["pseudonym"];
    assert_eq!(
        SigningKey::from_bytes(&a32(&p["pseudonym_seed"]))
            .verifying_key()
            .to_bytes()
            .to_vec(),
        h(&p["pseudonym_key"])
    );
    let ik = &v["invite_key"];
    assert_eq!(
        SigningKey::from_bytes(&a32(&ik["invite_seed"]))
            .verifying_key()
            .to_bytes()
            .to_vec(),
        h(&ik["invite_pk"])
    );

    // The committers digest over the set (sorted bytewise), §5.2 as corrected by §19.27 TR-6.
    let c = &v["committers"];
    let ch = h(&c["channel_id"]);
    let digest = |ks: &[Vec<u8>]| -> Vec<u8> {
        let mut s = ks.to_vec();
        s.sort();
        let mut hh = Sha256::new();
        hh.update(b"ghost/v1/ch/committers");
        hh.update(&ch);
        hh.update([s.len() as u8]);
        for k in &s {
            hh.update(k);
        }
        hh.finalize().to_vec()
    };
    let ks: Vec<Vec<u8>> = c["committers"].split(',').map(h).collect();
    assert_eq!(digest(&ks), h(&c["digest"]));
    let mut rev = ks.clone();
    rev.reverse();
    assert_eq!(digest(&rev), h(&c["digest_reordered"]));
    assert_eq!(digest(&ks[..2]), h(&c["digest_first_two"]));

    // The invite seal (§19.28.3): open ikm = salt; password ikm = Argon2id.
    let s = &v["invite_seal"];
    let isalt = h(&s["salt"]);
    assert_eq!(
        hkdf(&isalt, &isalt, &cat(&[b"ghost/v1/ch/invite-seal", &[0]])).to_vec(),
        h(&s["open_seal_key"])
    );
    let ikm = argon2id(&h(&s["password_nfkd_utf8"]), &isalt);
    assert_eq!(ikm.to_vec(), h(&s["argon2id_ikm"]));
    assert_eq!(
        hkdf(&ikm, &isalt, &cat(&[b"ghost/v1/ch/invite-seal", &[1]])).to_vec(),
        h(&s["password_seal_key"])
    );

    let r = &v["argon2id_rfc9106_5_3"];
    let params = argon2::ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(argon2::AssociatedData::new(&h(&r["associated_data"])).unwrap())
        .output_len(32)
        .build()
        .unwrap();
    let secret = h(&r["secret"]);
    let a = argon2::Argon2::new_with_secret(
        &secret,
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    )
    .unwrap();
    let mut out = [0u8; 32];
    a.hash_password_into(&h(&r["password"]), &h(&r["salt"]), &mut out)
        .unwrap();
    assert_eq!(out.to_vec(), h(&r["tag"]));
}

/// kdf_code 1: Argon2id, m = 65 536 KiB, t = 1, p = 4, T = 32, version 0x13 (§19.28.5).
fn argon2id(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let a = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65_536, 1, 4, Some(32)).unwrap(),
    );
    let mut o = [0u8; 32];
    a.hash_password_into(password, salt, &mut o).unwrap();
    o
}

// ---- ch_seal --------------------------------------------------------------------------------

fn hint(r: &[u8], mode: u8, salt: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(r).unwrap();
    m.update(b"ghost/v1/ch-hint");
    m.update(&[mode]);
    m.update(salt);
    m.finalize().into_bytes()[..16].to_vec()
}

fn seal_ad(ns: &[u8], bucket: u32, mode: u8) -> Vec<u8> {
    cat(&[
        b"ghost/v1/ch-seal",
        &[0x01],
        ns,
        &bucket.to_be_bytes(),
        &[mode],
    ])
}

fn my_seal(
    key: &[u8],
    ns: &[u8],
    bucket: usize,
    mode: u8,
    salt: &[u8],
    order: &[u8],
    body: &[u8],
) -> Vec<u8> {
    let r = hkdf(key, &[], b"ghost/v1/ch-recognition");
    let k = hkdf(key, salt, &cat(&[b"ghost/v1/ch-seal", ns]));
    let mut p = vec![mode];
    p.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    p.extend_from_slice(order);
    p.extend_from_slice(body);
    p.resize(bucket - 48, 0);
    let ct = ChaCha20Poly1305::new_from_slice(&k)
        .unwrap()
        .encrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: &p,
                aad: &seal_ad(ns, bucket as u32, mode),
            },
        )
        .unwrap();
    cat(&[salt, &hint(&r, mode, salt), &ct])
}

/// `Some((order, body))` when the blob opens under (key, ns, mode) and its P is canonical.
fn my_open(key: &[u8], ns: &[u8], mode: u8, blob: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let bucket = blob.len();
    if ![4096, 16_384, 65_536].contains(&bucket) {
        return None;
    }
    let r = hkdf(key, &[], b"ghost/v1/ch-recognition");
    let salt = &blob[..16];
    if hint(&r, mode, salt) != blob[16..32] {
        return None;
    }
    let k = hkdf(key, salt, &cat(&[b"ghost/v1/ch-seal", ns]));
    let p = ChaCha20Poly1305::new_from_slice(&k)
        .unwrap()
        .decrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: &blob[32..],
                aad: &seal_ad(ns, bucket as u32, mode),
            },
        )
        .ok()?;
    let len = u32::from_be_bytes([0, p[1], p[2], p[3]]) as usize;
    if p[0] != mode || len > bucket - 68 || p[20 + len..].iter().any(|&b| b != 0) {
        return None;
    }
    Some((p[4..20].to_vec(), p[20..20 + len].to_vec()))
}

#[test]
fn replay_ch_seal() {
    let v = load("ch_seal.txt");
    let mut blobs = 0;
    for (name, s) in &v {
        if !name.starts_with("mode_") {
            continue;
        }
        let key = h(&s["key"]);
        let ns = h(&s["ns"]);
        let bucket: usize = s["bucket"].parse().unwrap();
        let mode = u8::from_str_radix(&s["mode"], 16).unwrap();
        let salt = h(&s["salt"]);
        let order = h(&s["order"]);
        let body = h(&s["body"]);
        let blob = my_seal(&key, &ns, bucket, mode, &salt, &order, &body);
        assert_eq!(blob.len(), bucket);
        assert_eq!(blob[16..32].to_vec(), h(&s["hint"]), "{name}");
        assert_eq!(
            Sha256::digest(&blob).to_vec(),
            h(&s["blob_sha256"]),
            "{name}"
        );
        if let Some(full) = s.get("blob") {
            assert_eq!(blob, h(full), "{name}");
        }
        assert_eq!(
            my_open(&key, &ns, mode, &blob),
            Some((order.clone(), body.clone())),
            "{name}"
        );
        if let Some(refused) = s.get("refused") {
            for m in refused.split(',') {
                let (b2, ns2, mode2) = match m {
                    "flip_byte_40" => {
                        let mut b = blob.clone();
                        b[40] ^= 1;
                        (b, ns.clone(), mode)
                    }
                    "flip_byte_20" => {
                        let mut b = blob.clone();
                        b[20] ^= 1;
                        (b, ns.clone(), mode)
                    }
                    "truncate_1" => (blob[..blob.len() - 1].to_vec(), ns.clone(), mode),
                    "other_ns" => {
                        let mut n = ns.clone();
                        n[0] ^= 1;
                        (blob.clone(), n, mode)
                    }
                    "other_mode" => (
                        blob.clone(),
                        ns.clone(),
                        if mode == 0x12 { 0x13 } else { 0x12 },
                    ),
                    other => panic!("unknown mutation {other}"),
                };
                assert_eq!(
                    my_open(&key, &ns2, mode2, &b2),
                    None,
                    "{name}: {m} must not open"
                );
            }
        }
        blobs += 1;
    }
    assert_eq!(blobs, 9, "three modes x three buckets");
    let c = &v["capacity"];
    for b in [4096usize, 16_384, 65_536] {
        assert_eq!(c[&format!("c_{b}")], (b - 68).to_string());
    }
    // bucket(len) = min { B : B >= floor(class) and C(B) >= len } (§5.7).
    let bucket = |len: usize, floor: usize| {
        [4096usize, 16_384, 65_536]
            .into_iter()
            .find(|&b| b >= floor && b - 68 >= len)
    };
    assert_eq!(
        c["bucket_small_4028"],
        bucket(4028, 4096).unwrap().to_string()
    );
    assert_eq!(
        c["bucket_small_4029"],
        bucket(4029, 4096).unwrap().to_string()
    );
    assert_eq!(c["bucket_large_1"], bucket(1, 16_384).unwrap().to_string());
    assert!(bucket(c["no_fit"].parse().unwrap(), 4096).is_none());
    // §5.8's table, written out from the design text.
    let table = [
        (2_592_000, 2_592_000, 604_800),
        (3_600, 604_800, 3_600),
        (3_600, 604_800, 3_600),
        (86_400, 604_800, 86_400),
        (604_800, 604_800, 604_800),
        (2_592_000, 2_592_000, 604_800),
    ];
    for (code, (p, hs, d)) in table.iter().enumerate() {
        assert_eq!(
            v["ttl"][&format!("timer_{code}")],
            format!("post={p} handshake={hs} deadline={d}")
        );
    }
}

// ---- ch_content -----------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
struct Content {
    kind: u8,
    op_id: Vec<u8>,
    author_minute: u32,
    timer_code: u8,
    tlvs: Vec<(u16, Vec<u8>)>,
}

/// §5.5, independently: header, TLVs strictly ascending, only the TLVs of the kind, the bounds.
fn decode_content(b: &[u8]) -> Option<Content> {
    if b.len() < 23 || b[0] != 1 || b[22] > 5 {
        return None;
    }
    let mut tlvs = Vec::new();
    let mut i = 23;
    while i < b.len() {
        if i + 4 > b.len() {
            return None;
        }
        let t = u16::from_be_bytes([b[i], b[i + 1]]);
        let l = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
        if i + 4 + l > b.len() {
            return None;
        }
        if tlvs.last().is_some_and(|(p, _): &(u16, Vec<u8>)| *p >= t) {
            return None;
        }
        tlvs.push((t, b[i + 4..i + 4 + l].to_vec()));
        i += 4 + l;
    }
    let get = |t: u16| tlvs.iter().find(|(x, _)| *x == t).map(|(_, v)| v.clone());
    let only = |allowed: &[u16]| tlvs.iter().all(|(t, _)| allowed.contains(t));
    let ok = match b[1] {
        1 => {
            only(&[1, 2])
                && get(1).is_some_and(|t| {
                    !t.is_empty() && t.len() <= 16_000 && std::str::from_utf8(&t).is_ok()
                })
                && get(2).is_none_or(|r| r.len() == 16)
        }
        2 => {
            only(&[4, 5])
                && get(4).is_some_and(|t| t.len() == 16)
                && get(5).is_some_and(|g| g.len() <= 32 && std::str::from_utf8(&g).is_ok())
        }
        3 => {
            only(&[0x10, 0x11, 0x12, 0x13, 0x14, 0x15])
                && get(0x10).is_some_and(|v| v.len() == 16)
                && get(0x11).is_some_and(|v| v.len() == 32)
                && get(0x12).is_some_and(|v| v.len() == 4)
                && get(0x13).is_some_and(|v| v.len() == 64)
                && get(0x14).is_some_and(|v| v.len() == 32)
                && get(0x15).is_none_or(|v| v.len() == 2 && v != [0, 0])
        }
        4 => tlvs.is_empty(),
        5 => {
            only(&[0x20, 0x21])
                && get(0x20).is_some_and(|v| v.len() == 32)
                && get(0x21).is_some_and(|v| v.len() <= 512)
        }
        _ => false,
    };
    ok.then(|| Content {
        kind: b[1],
        op_id: b[2..18].to_vec(),
        author_minute: u32::from_be_bytes([b[18], b[19], b[20], b[21]]),
        timer_code: b[22],
        tlvs,
    })
}

fn encode_content(c: &Content) -> Vec<u8> {
    let mut o = vec![1, c.kind];
    o.extend_from_slice(&c.op_id);
    o.extend_from_slice(&c.author_minute.to_be_bytes());
    o.push(c.timer_code);
    for (t, v) in &c.tlvs {
        o.extend_from_slice(&t.to_be_bytes());
        o.extend_from_slice(&(v.len() as u16).to_be_bytes());
        o.extend_from_slice(v);
    }
    o
}

#[test]
fn replay_ch_content() {
    let v = load("ch_content.txt");
    let (mut ok, mut bad) = (0, 0);
    for (name, s) in &v {
        if let Some(rest) = name.strip_prefix("ok_") {
            let b = h(&s["bytes"]);
            let c = decode_content(&b).unwrap_or_else(|| panic!("{name} does not decode"));
            assert_eq!(encode_content(&c), b, "{name} re-encodes to itself");
            assert_eq!(c.kind.to_string(), s["kind"]);
            assert_eq!(c.op_id, h(&s["op_id"]));
            assert_eq!(c.author_minute.to_string(), s["author_minute"]);
            assert_eq!(c.timer_code.to_string(), s["timer_code"]);
            let tlv = |t: u16| c.tlvs.iter().find(|(x, _)| *x == t).map(|(_, v)| v.clone());
            match c.kind {
                1 => {
                    assert_eq!(tlv(1).unwrap(), h(&s["text"]));
                    assert_eq!(tlv(2).map_or("-".to_string(), hex::encode), s["reply_to"]);
                }
                2 => {
                    assert_eq!(tlv(4).unwrap(), h(&s["target"]));
                    assert_eq!(tlv(5).unwrap(), h(&s["grapheme"]));
                }
                3 => {
                    assert_eq!(tlv(0x10).unwrap(), h(&s["invite_id"]));
                    assert_eq!(tlv(0x11).unwrap(), h(&s["invite_pk"]));
                    let e = tlv(0x12).unwrap();
                    assert_eq!(
                        u32::from_be_bytes([e[0], e[1], e[2], e[3]]).to_string(),
                        s["expiry_day"]
                    );
                    assert_eq!(tlv(0x13).unwrap(), h(&s["sponsor_sig"]));
                    assert_eq!(tlv(0x14).unwrap(), h(&s["committers_digest"]));
                    let pw = tlv(0x15).map_or("-".to_string(), |p| {
                        u16::from_be_bytes([p[0], p[1]]).to_string()
                    });
                    assert_eq!(pw, s["pw_version"]);
                }
                4 => {}
                5 => {
                    assert_eq!(tlv(0x20).unwrap(), h(&s["hpke_enc"]));
                    assert_eq!(tlv(0x21).unwrap(), h(&s["ciphertext"]));
                }
                _ => unreachable!(),
            }
            let _ = rest;
            ok += 1;
        } else if name.starts_with("bad_") {
            let b = match (s.get("bytes"), s.get("recipe")) {
                (Some(x), _) => h(x),
                (None, Some(r)) => {
                    // "ok_post header, kind 1, tlv 0x0001 of N bytes 0x61"
                    let n: usize = r.split_whitespace().nth(7).unwrap().parse().unwrap();
                    let mut b = h(&v["ok_post"]["bytes"])[..23].to_vec();
                    b[1] = 1;
                    b.extend_from_slice(&1u16.to_be_bytes());
                    b.extend_from_slice(&(n as u16).to_be_bytes());
                    b.extend(std::iter::repeat_n(b'a', n));
                    b
                }
                _ => panic!("{name}"),
            };
            assert!(decode_content(&b).is_none(), "{name} must be NON_CANONICAL");
            bad += 1;
        }
    }
    assert_eq!((ok, bad), (8, 17));
    assert_eq!(v["sizes"]["longest_text_post_content"], "16027");
}

// ---- ch_invite ------------------------------------------------------------------------------

fn base32(data: &[u8]) -> String {
    // RFC 4648 §6, lowercase, no padding.
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bits = String::new();
    for b in data {
        bits.push_str(&format!("{b:08b}"));
    }
    while !bits.len().is_multiple_of(5) {
        bits.push('0');
    }
    bits.as_bytes()
        .chunks(5)
        .map(|c| {
            alphabet[usize::from_str_radix(std::str::from_utf8(c).unwrap(), 2).unwrap()] as char
        })
        .collect()
}

#[test]
fn replay_ch_invite() {
    let v = load("ch_invite.txt");
    let mut n = 0;
    for (name, s) in &v {
        if name == "refusals" {
            continue;
        }
        let kdf: u8 = s["kdf_code"].parse().unwrap();
        let salt = h(&s["salt"]);
        let name_bytes = h(&s["name"]);
        // The inner body: the V1 fields from suite to name (§5.9), zero-padded to 301.
        let mut inner = cat(&[
            &h(&s["suite"]),
            &[
                s["size_class"].parse::<u8>().unwrap(),
                s["handshake_ttl_code"].parse::<u8>().unwrap(),
            ],
            &h(&s["channel_id"]),
            &s["generation"].parse::<u32>().unwrap().to_be_bytes(),
            &h(&s["ns"]),
            &h(&s["read_base"]),
            &h(&s["deposit_base"]),
            &h(&s["join_key"]),
            &h(&s["invite_id"]),
            &h(&s["invite_seed"]),
            &h(&s["committers_digest"]),
            &s["expiry_day"].parse::<u32>().unwrap().to_be_bytes(),
            &[name_bytes.len() as u8],
            &name_bytes,
        ]);
        assert_eq!(inner.len(), 253 + name_bytes.len());
        inner.resize(301, 0);
        let header = cat(&[&[2, kdf], &salt]);
        let ikm = if kdf == 0 {
            salt.clone()
        } else {
            argon2id(&h(&s["password"]), &salt).to_vec()
        };
        let k = hkdf(&ikm, &salt, &cat(&[b"ghost/v1/ch/invite-seal", &[kdf]]));
        let ct = ChaCha20Poly1305::new_from_slice(&k)
            .unwrap()
            .encrypt(
                &Nonce::from([0u8; 12]),
                Payload {
                    msg: &inner,
                    aad: &cat(&[b"ghost/v1/ch/invite-v2", &header]),
                },
            )
            .unwrap();
        let invite = cat(&[&header, &ct]);
        assert_eq!(invite.len(), 335, "{name}");
        assert_eq!(invite, h(&s["invite"]), "{name}");
        let link = format!("ghost://channel/{}", base32(&invite));
        assert_eq!(link.len(), 552);
        assert_eq!(link, s["link"]);
        assert_eq!(
            SigningKey::from_bytes(&a32(&s["invite_seed"]))
                .verifying_key()
                .to_bytes()
                .to_vec(),
            h(&s["invite_pk"])
        );
        // The refusals of [refusals]: a wrong password and tampered bytes do not open.
        if kdf == 1 {
            let wrong = argon2id(v["refusals"]["wrong_password"].as_bytes(), &salt);
            let kw = hkdf(&wrong, &salt, &cat(&[b"ghost/v1/ch/invite-seal", &[1]]));
            let open = |key: &[u8], bytes: &[u8]| {
                ChaCha20Poly1305::new_from_slice(key)
                    .unwrap()
                    .decrypt(
                        &Nonce::from([0u8; 12]),
                        Payload {
                            msg: &bytes[18..],
                            aad: &cat(&[b"ghost/v1/ch/invite-v2", &bytes[..18]]),
                        },
                    )
                    .is_ok()
            };
            assert!(open(&k, &invite));
            assert!(!open(&kw, &invite));
            let mut flip = invite.clone();
            flip[40] ^= 1;
            assert!(!open(&k, &flip));
            let mut down = invite.clone();
            down[1] = 0;
            let k0 = hkdf(&salt, &salt, &cat(&[b"ghost/v1/ch/invite-seal", &[0]]));
            assert!(!open(&k0, &down), "an open key never opens a password link");
        }
        n += 1;
    }
    assert_eq!(n, 4);
    assert_eq!(v["refusals"]["link_characters"], "552");
}

// ---- ch_join: RFC 9420 structures, independently ----------------------------------------------

struct R<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        s
    }
    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }
    fn u16(&mut self) -> u16 {
        let s = self.take(2);
        u16::from_be_bytes([s[0], s[1]])
    }
    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.take(8).try_into().unwrap())
    }
    /// RFC 9420 §2.1.2: a varint length, minimal.
    fn vlen(&mut self) -> usize {
        let f = self.b[self.i];
        match f >> 6 {
            0 => {
                self.i += 1;
                usize::from(f & 0x3f)
            }
            1 => {
                let v = usize::from(u16::from_be_bytes([f & 0x3f, self.b[self.i + 1]]));
                assert!(v >= 64, "non-minimal varint");
                self.i += 2;
                v
            }
            _ => panic!("vector longer than 16 383 in a KeyPackage"),
        }
    }
    fn vec(&mut self) -> &'a [u8] {
        let n = self.vlen();
        self.take(n)
    }
}

fn vbytes(v: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    if v.len() < 64 {
        o.push(v.len() as u8);
    } else {
        o.extend_from_slice(&((v.len() as u16) | 0x4000).to_be_bytes());
    }
    o.extend_from_slice(v);
    o
}

/// RFC 9420 §5.1.2 VerifyWithLabel.
fn verify_with_label(pk: &[u8], label: &str, content: &[u8], sig: &[u8]) -> bool {
    let sign_content = cat(&[
        &vbytes(format!("MLS 1.0 {label}").as_bytes()),
        &vbytes(content),
    ]);
    VerifyingKey::from_bytes(&pk.try_into().unwrap())
        .unwrap()
        .verify_strict(
            &sign_content,
            &Signature::from_bytes(&sig.try_into().unwrap()),
        )
        .is_ok()
}

#[test]
fn replay_ch_join() {
    let v = load("ch_join.txt");
    let kp = &v["key_package"];
    let bytes = h(&kp["bytes"]);
    assert_eq!(bytes.len(), 395);
    let mut r = R { b: &bytes, i: 0 };
    // MLSMessage: version mls10 (1), wire_format mls_key_package (5).
    assert_eq!((r.u16(), r.u16()), (1, 5));
    let kp_start = r.i;
    assert_eq!(r.u16(), 1, "KeyPackage.version");
    assert_eq!(r.u16(), 3, "cipher_suite 0x0003");
    assert_eq!(r.vec().len(), 32, "init_key (X25519)");
    let leaf_start = r.i;
    assert_eq!(r.vec().len(), 32, "encryption_key");
    let sig_key = r.vec().to_vec();
    assert_eq!(
        sig_key,
        h(&kp["pseudonym_key"]),
        "signature_key = the pseudonym key"
    );
    assert_eq!(r.u16(), 1, "credential type basic");
    assert_eq!(
        r.vec(),
        sig_key.as_slice(),
        "BasicCredential identity = signature key"
    );
    // Capabilities exactly: versions [mls10], suites [0x0003], extensions [f0a1, f0a2, f0a4],
    // proposals [], credentials [basic] (§6.2.4 (B)); no GREASE.
    assert_eq!(r.vec(), [0, 1]);
    assert_eq!(r.vec(), [0, 3]);
    assert_eq!(r.vec(), [0xf0, 0xa1, 0xf0, 0xa2, 0xf0, 0xa4]);
    assert_eq!(r.vec(), [] as [u8; 0]);
    assert_eq!(r.vec(), [0, 1]);
    // leaf_node_source key_package (1) with the constant lifetime [0, 2^64 - 1] (Q42 (a)).
    assert_eq!(r.u8(), 1);
    assert_eq!((r.u64(), r.u64()), (0, u64::MAX));
    // Leaf extensions exactly [GhostLeaf(v1, box_pk, refresh_epoch 0)].
    let exts = r.vec().to_vec();
    let leaf_tbs_end = r.i;
    let mut e = R { b: &exts, i: 0 };
    assert_eq!(e.u16(), 0xf0a2);
    let gl = e.vec().to_vec();
    assert_eq!(e.i, exts.len(), "one leaf extension");
    assert_eq!((gl.len(), gl[0]), (41, 1));
    assert_eq!(gl[1..33].to_vec(), h(&kp["box_pk"]));
    assert_eq!(gl[33..41], [0u8; 8], "refresh_epoch 0 in a KeyPackage leaf");
    let leaf_sig = r.vec().to_vec();
    assert!(verify_with_label(
        &sig_key,
        "LeafNodeTBS",
        &bytes[leaf_start..leaf_tbs_end],
        &leaf_sig
    ));
    // KeyPackage extensions exactly [GhostKpBind].
    let kexts = r.vec().to_vec();
    let kp_tbs_end = r.i;
    let mut ke = R { b: &kexts, i: 0 };
    assert_eq!(ke.u16(), 0xf0a4);
    let bind = ke.vec().to_vec();
    assert_eq!(ke.i, kexts.len(), "one KeyPackage extension");
    assert_eq!(bind, h(&kp["kp_bind"]));
    assert_eq!(
        (bind.len(), bind[0], bind[33]),
        (38, 1, 1),
        "GhostKpBind v1, purpose join"
    );
    let kp_sig = r.vec().to_vec();
    assert_eq!(r.i, 395, "nothing after the KeyPackage");
    assert!(verify_with_label(
        &sig_key,
        "KeyPackageTBS",
        &bytes[kp_start..kp_tbs_end],
        &kp_sig
    ));
    // MakeKeyPackageRef (RFC 9420 §5.2): RefHash("MLS 1.0 KeyPackage Reference", KeyPackage).
    let kp_value = &bytes[kp_start..];
    let reference = Sha256::digest(cat(&[
        &vbytes(b"MLS 1.0 KeyPackage Reference"),
        &vbytes(kp_value),
    ]));
    assert_eq!(reference.to_vec(), h(&kp["kp_ref"]));
    assert_eq!(Sha256::digest(&bytes).to_vec(), h(&kp["sha256"]));

    // The join request (§5.6): invite_sig under the invite key.
    let jr = &v["join_request"];
    let ch = h(&jr["channel_id"]);
    let ik = SigningKey::from_bytes(&a32(&jr["invite_seed"]));
    let msg = cat(&[
        b"ghost/v1/ch/join",
        &ch,
        &h(&jr["invite_id"]),
        &Sha256::digest(&bytes),
    ]);
    assert_eq!(msg, h(&jr["invite_sig_message"]));
    assert_eq!(ik.sign(&msg).to_bytes().to_vec(), h(&jr["invite_sig"]));
    let body = cat(&[
        &[1, 1],
        &395u16.to_be_bytes(),
        &bytes,
        &h(&jr["invite_id"]),
        &h(&jr["invite_sig"]),
    ]);
    assert_eq!(body, h(&jr["body"]));

    // The rejoin request (§19.3): rejoin_sig under the pseudonym key.
    let rj = &v["rejoin_request"];
    let pk = SigningKey::from_bytes(&a32(&rj["pseudonym_seed"]));
    let (g, d, le): (u32, u32, u64) = (
        rj["generation"].parse().unwrap(),
        rj["day"].parse().unwrap(),
        rj["last_epoch"].parse().unwrap(),
    );
    let rmsg = cat(&[
        b"ghost/v1/ch/rejoin",
        &ch,
        &g.to_be_bytes(),
        &d.to_be_bytes(),
        &le.to_be_bytes(),
        &h(&rj["last_hash"]),
        &Sha256::digest(&bytes),
    ]);
    assert_eq!(rmsg, h(&rj["rejoin_sig_message"]));
    assert_eq!(pk.sign(&rmsg).to_bytes().to_vec(), h(&rj["rejoin_sig"]));
    let rbody = cat(&[
        &[1, 2],
        &395u16.to_be_bytes(),
        &bytes,
        &d.to_be_bytes(),
        &le.to_be_bytes(),
        &h(&rj["last_hash"]),
        &h(&rj["rejoin_sig"]),
    ]);
    assert_eq!(rbody, h(&rj["body"]));

    // sponsor_sig (§5.5 TLV 0x0013).
    let sp = &v["sponsor_sig"];
    let sk = SigningKey::from_bytes(&a32(&sp["sponsor_seed"]));
    assert_eq!(
        sk.verifying_key().to_bytes().to_vec(),
        h(&sp["sponsor_key"])
    );
    let smsg = cat(&[
        b"ghost/v1/ch/invite",
        &ch,
        &h(&jr["invite_id"]),
        &h(&sp["invite_pk"]),
        &sp["expiry_day"].parse::<u32>().unwrap().to_be_bytes(),
    ]);
    assert_eq!(smsg, h(&sp["message"]));
    assert_eq!(sk.sign(&smsg).to_bytes().to_vec(), h(&sp["sponsor_sig"]));

    // WelcomeBlob (§5.6).
    let wb = &v["welcome_blob"];
    let kr = h(&wb["kp_ref"]);
    let w = h(&wb["welcome"]);
    let enc = cat(&[
        &[1, kr.len() as u8],
        &kr,
        &(w.len() as u32).to_be_bytes()[1..],
        &w,
    ]);
    assert_eq!(enc, h(&wb["bytes"]));

    // GhostChannelContext (§5.3): the largest is 448 bytes; fields at their offsets.
    let cc = &v["channel_context"];
    let max = h(&cc["max"]);
    assert_eq!(max.len(), 448);
    assert_eq!(cc["max_length"], "448");
    let mut r = R { b: &max, i: 0 };
    assert_eq!(r.u8(), 1);
    assert_eq!(r.take(32), ch.as_slice());
    assert_eq!(
        (r.u8(), r.u8(), r.u16(), r.u8(), r.u8(), r.u16(), r.u16()),
        (1, 5, 513, 0, 0b100, 70, 3)
    );
    assert_eq!(r.vec(), [b'a'; 48]);
    assert_eq!(r.vec().len(), 256);
    assert_eq!(r.vec().len(), 96);
    assert_eq!(r.i, max.len());
    let init = h(&cc["initial"]);
    assert_eq!(init.len(), 43 + 1 + 1 + 32 + 1 + 32);

    // GhostLeaf, GhostKpBind, GhostBootstrap, ChannelOrder (§5.4, §5.5).
    let gl = h(&v["ghost_leaf"]["bytes"]);
    assert_eq!(
        (gl.len(), gl[0], &gl[33..]),
        (41, 1, &9u64.to_be_bytes()[..])
    );
    let kb = h(&v["kp_bind"]["bytes"]);
    assert_eq!(
        (kb.len(), kb[0], &kb[1..33], kb[33], &kb[34..]),
        (38, 1, ch.as_slice(), 3, &20_725u32.to_be_bytes()[..])
    );
    let bs = h(&v["bootstrap"]["bytes"]);
    assert_eq!(
        (bs.len(), bs[0], &bs[1..5], &bs[5..13]),
        (45, 1, &2u32.to_be_bytes()[..], &17u64.to_be_bytes()[..])
    );
    assert_eq!(
        h(&v["channel_order"]["bytes"]),
        cat(&[&[1], &3u32.to_be_bytes(), &12u32.to_be_bytes()])
    );

    // GhostCommitAad (§19.2): version, commit_minute, flags (bit 0 rotate), admits<V>, swaps<V>.
    let aad = h(&v["commit_aad"]["bytes"]);
    let mut r = R { b: &aad, i: 0 };
    assert_eq!(r.u8(), 1);
    assert_eq!(
        u32::from_be_bytes(r.take(4).try_into().unwrap()),
        29_844_000
    );
    assert_eq!(r.u8(), 1, "rotate");
    let admits = r.vec().to_vec();
    let swaps = r.vec().to_vec();
    assert_eq!(r.i, aad.len());
    // One admit: kp_ref<V> 1+32, invite_id 16, invite_pk 32, expiry 4, sponsor 32, two signatures.
    assert_eq!(admits.len(), 33 + 16 + 32 + 4 + 32 + 64 + 64);
    assert_eq!(&admits[1..33], kr.as_slice());
    // Two swaps: a rejoin (kind 1) and a restore (kind 2, with its own admit evidence).
    assert_eq!(swaps.len(), (33 + 1 + 4 + 4 + 8 + 32 + 64) + (33 + 1 + 245));
    assert_eq!(swaps[33], 1);
    assert_eq!(swaps[33 + 113 + 33], 2);
    assert_eq!(h(&v["commit_aad"]["empty"]), [1, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn replay_ch_sizes() {
    let v = load("ch_sizes.txt");
    let s = &v["sizes"];
    // The canonical KeyPackage's size from RFC 9420's encoding of its fields (§6.2.4 (B)): the
    // MLSMessage header 4; version 2, suite 2, init_key<V> 33; the leaf: encryption_key<V> 33,
    // signature_key<V> 33, credential 2 + 33, capabilities 3 + 3 + 7 + 1 + 3, source 1, lifetime 16,
    // extensions<V> 1 + (2 + 1 + 41), signature<V> 2 + 64; extensions<V> 1 + (2 + 1 + 38);
    // signature<V> 2 + 64 (64 needs a two-byte varint).
    let leaf = 33 + 33 + (2 + 33) + (3 + 3 + 7 + 1 + 3) + 1 + 16 + (1 + 2 + 1 + 41) + (2 + 64);
    let kp = 4 + 2 + 2 + 33 + leaf + (1 + 2 + 1 + 38) + (2 + 64);
    assert_eq!(kp, 395);
    assert_eq!(s["key_package"], kp.to_string());
    // The longest posts fit C(16384) with the stated margins.
    for k in ["post_16000", "post_16000_reply_to"] {
        let (n, rest) = s[k].split_once(' ').unwrap();
        let n: usize = n.parse().unwrap();
        assert_eq!(rest, format!("(margin {} to C(16384))", 16_316 - n));
    }
    // Every single-proposal commit at the small cap fits C(4096) = 4028 (§5.7), margins as stated.
    for k in [
        "add_31_to_32",
        "self_update_rank_255",
        "pcs_commit",
        "remove_1",
        "swap_rejoin",
        "swap_restore",
        "context_change_max",
        "remove_1_with_context_change",
        "remove_committer_with_drop_of_its_key",
    ] {
        let (n, rest) = s[k].split_once(' ').unwrap();
        let n: usize = n.parse().unwrap();
        assert!(n <= 4028, "{k}");
        assert_eq!(rest, format!("(margin {})", 4028 - n));
    }
    let w: usize = s["welcome_one_joiner_32"].parse().unwrap();
    assert!(
        w > 4028 && w <= 16_316,
        "a 32-member Welcome takes the 16 KiB bucket"
    );
}
