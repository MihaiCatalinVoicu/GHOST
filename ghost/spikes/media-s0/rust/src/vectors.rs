//! The §3.9 vector file (`vectors/media_object.txt`, the future
//! `protocol/test-vectors/media_object.txt`), generated deterministically from fixed inputs.
//! `tests/vectors.rs` fails if the committed file differs; `jvm/MediaVectors.java` replays it with
//! JCA ChaCha20-Poly1305 and an HMAC-SHA256 HKDF written from RFC 5869 (the F9 practice of two
//! independent implementations of every vector).

use crate::format::*;
use crate::{hex, sha256};
use std::fmt::Write;

/// One positive object case.
pub struct Case {
    pub name: &'static str,
    pub k_f: [u8; 32],
    pub object_id: [u8; 16],
    pub kind: u8,
    pub flags: u8,
    pub content_seed: &'static str,
    pub content_len: usize,
    pub facts: StreamFacts,
    pub preview_seed: &'static str,
    pub preview_len: usize,
    pub caption: &'static str,
    pub dest_id: [u8; 16],
    pub state_key: [u8; 32],
    pub wrap_nonce: [u8; 12],
}

fn seq<const N: usize>(start: u8) -> [u8; N] {
    let mut a = [0u8; N];
    for (i, b) in a.iter_mut().enumerate() {
        *b = start.wrapping_add(i as u8);
    }
    a
}

pub fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "image-class0",
            k_f: seq(0x00),
            object_id: seq(0xa0),
            kind: KIND_IMAGE,
            flags: 0,
            content_seed: "ghost/v1/media/test/image-class0",
            content_len: 1_000_000,
            facts: StreamFacts {
                width: 2048,
                height: 1536,
                duration_ms: 0,
            },
            preview_seed: "ghost/v1/media/test/preview",
            preview_len: 20_000,
            caption: "o fotografie",
            dest_id: seq(0x40),
            state_key: seq(0x60),
            wrap_nonce: seq(0x80),
        },
        Case {
            name: "video-class0-full",
            k_f: seq(0x10),
            object_id: seq(0xb0),
            kind: KIND_VIDEO,
            flags: 0,
            content_seed: "ghost/v1/media/test/video-class0-full",
            content_len: IMAGE_MAX_CONTENT as usize,
            facts: StreamFacts {
                width: 720,
                height: 1280,
                duration_ms: 3_900,
            },
            preview_seed: "ghost/v1/media/test/preview",
            preview_len: 32_768,
            caption: "",
            dest_id: seq(0x41),
            state_key: seq(0x61),
            wrap_nonce: seq(0x81),
        },
        Case {
            name: "video-class1-view-once",
            k_f: seq(0x20),
            object_id: seq(0xc0),
            kind: KIND_VIDEO,
            flags: FLAG_VIEW_ONCE,
            content_seed: "ghost/v1/media/test/video-class1",
            content_len: IMAGE_MAX_CONTENT as usize + 1,
            facts: StreamFacts {
                width: 1280,
                height: 720,
                duration_ms: 5_021,
            },
            preview_seed: "",
            preview_len: 0,
            caption: "vezi o singură dată",
            dest_id: seq(0x42),
            state_key: seq(0x62),
            wrap_nonce: seq(0x82),
        },
    ]
}

pub struct Built {
    pub content: Vec<u8>,
    pub preview: Vec<u8>,
    pub object: SealedObject,
    pub descriptor: Descriptor,
    pub key_env_out: Vec<u8>,
    pub key_env_in: Vec<u8>,
}

/// The nonce of the recipient-side wrap: the case's wrap nonce with its first byte inverted.
pub fn wrap_nonce_in(c: &Case) -> [u8; 12] {
    let mut n = c.wrap_nonce;
    n[0] ^= 0xff;
    n
}

pub fn build(c: &Case) -> Built {
    let content = sha256ctr(c.content_seed.as_bytes(), c.content_len);
    let preview = sha256ctr(c.preview_seed.as_bytes(), c.preview_len);
    let object = seal_object(
        &c.k_f,
        &c.object_id,
        c.kind,
        c.flags,
        &content,
        c.facts,
        &preview,
        100_000,
    )
    .expect("vector case seals");
    let descriptor = Descriptor {
        kind: c.kind,
        flags: c.flags,
        class_code: object.class_code,
        object_id: c.object_id,
        key_slot: [0; 32],
        manifest_hash: object.manifest_hash,
        caption: c.caption.as_bytes().to_vec(),
    };
    let key_env_out = wrap_key_env(
        &c.state_key,
        &c.wrap_nonce,
        &key_env_binding(ROLE_OUT, &c.dest_id, &c.object_id, &object.manifest_hash),
        &c.k_f,
    );
    // A wrap draws a fresh random nonce in production; the two roles' vectors therefore use two
    // different fixed nonces, so the vector set never shows one (state_key, nonce) sealing twice.
    let key_env_in = wrap_key_env(
        &c.state_key,
        &wrap_nonce_in(c),
        &key_env_binding(ROLE_IN, &c.dest_id, &c.object_id, &object.manifest_hash),
        &c.k_f,
    );
    Built {
        content,
        preview,
        object,
        descriptor,
        key_env_out,
        key_env_in,
    }
}

/// The whole vector file.
pub fn render() -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "# GHOST Phase 11 media object vectors (docs/design/faza11-media.md §3.9), S0 evidence."
    );
    let _ = writeln!(s, "# Generated by ghost/spikes/media-s0/rust (src/vectors.rs; tests/vectors.rs fails on any difference).");
    let _ = writeln!(s, "# Replayed independently by ghost/spikes/media-s0/jvm/MediaVectors.java (JCA ChaCha20-Poly1305, RFC 5869 HKDF).");
    let _ = writeln!(s, "# sha256ctr(seed, len) = SHA-256(seed || u32_be(0)) || SHA-256(seed || u32_be(1)) || ... truncated to len; seeds are UTF-8.");
    let _ = writeln!(s);
    let _ = writeln!(s, "[constants]");
    let _ = writeln!(s, "FRAG = {FRAG}");
    let _ = writeln!(s, "CHUNK_CT = {CHUNK_CT}");
    let _ = writeln!(s, "CHUNK_PT = {CHUNK_PT}");
    let _ = writeln!(s, "MANIFEST_PT = {MANIFEST_PT}");
    let _ = writeln!(s, "HASHES_OFFSET = {HASHES_OFFSET}");
    let _ = writeln!(s, "IMAGE_MAX_CONTENT = {IMAGE_MAX_CONTENT}");
    let _ = writeln!(s, "MAX_CONTENT = {MAX_CONTENT}");
    let _ = writeln!(s);
    let _ = writeln!(s, "[classes]");
    for (code, &f) in CLASSES.iter().enumerate() {
        let cap = class_capacity(code as u8);
        let _ = writeln!(
            s,
            "class = {code} F = {f} chunks = {} cap = {cap} blobs = {} bytes_per_relay = {}",
            f / 4,
            f + 1,
            (f + 1) * FRAG
        );
    }
    let mut boundaries = vec![1u64];
    for code in 0..11u8 {
        let cap = class_capacity(code).min(MAX_CONTENT);
        boundaries.push(cap);
        boundaries.push(cap + 1);
    }
    for len in boundaries {
        let _ = writeln!(
            s,
            "boundary len = {len} class = {}",
            class_code_for(len)
                .map(|c| c.to_string())
                .unwrap_or_else(|| "none".into())
        );
    }
    let _ = writeln!(s, "boundary len = 0 class = none");
    let _ = writeln!(s);
    for c in cases() {
        let b = build(&c);
        let keys = derive(&c.k_f, &c.object_id);
        let _ = writeln!(s, "[object {}]", c.name);
        let _ = writeln!(s, "k_f = {}", hex(&c.k_f));
        let _ = writeln!(s, "object_id = {}", hex(&c.object_id));
        let _ = writeln!(s, "kind = {}", c.kind);
        let _ = writeln!(s, "flags = {}", c.flags);
        let _ = writeln!(
            s,
            "content = sha256ctr({:?}, {})",
            c.content_seed, c.content_len
        );
        let _ = writeln!(s, "content_sha256 = {}", hex(&sha256(&b.content)));
        let _ = writeln!(s, "width = {}", c.facts.width);
        let _ = writeln!(s, "height = {}", c.facts.height);
        let _ = writeln!(s, "duration_ms = {}", c.facts.duration_ms);
        let _ = writeln!(
            s,
            "preview = sha256ctr({:?}, {})",
            c.preview_seed, c.preview_len
        );
        let _ = writeln!(s, "k_p = {}", hex(&keys.k_p));
        let _ = writeln!(s, "k_m = {}", hex(&keys.k_m));
        let _ = writeln!(s, "commit = {}", hex(&keys.commit));
        let _ = writeln!(s, "class_code = {}", b.object.class_code);
        let n = CLASSES[b.object.class_code as usize] / 4;
        for i in 0..n as u32 {
            let _ = writeln!(
                s,
                "chunk_nonce[{i}] = {}",
                hex(&chunk_nonce(i, i == n as u32 - 1))
            );
        }
        let _ = writeln!(s, "chunk_ad = {}", hex(&chunk_ad(&c.object_id, c.kind)));
        for (j, f) in b.object.fragments.iter().enumerate() {
            let _ = writeln!(s, "fragment_sha256[{j}] = {}", hex(&sha256(f)));
        }
        let mp = b.object.manifest.encode().expect("encodes");
        let _ = writeln!(
            s,
            "manifest_ad = {}",
            hex(&manifest_ad(&c.object_id, &keys.commit))
        );
        let _ = writeln!(s, "manifest_plaintext_head = {}", hex(&mp[..38]));
        let _ = writeln!(s, "manifest_plaintext_sha256 = {}", hex(&sha256(&mp)));
        let _ = writeln!(s, "manifest_hash = {}", hex(&b.object.manifest_hash));
        let _ = writeln!(
            s,
            "manifest_blob_tail16 = {}",
            hex(&b.object.manifest_blob[FRAG - 16..])
        );
        let _ = writeln!(s, "caption = {:?}", c.caption);
        let _ = writeln!(s, "descriptor = {}", hex(&b.descriptor.encode()));
        let _ = writeln!(s, "dest_id = {}", hex(&c.dest_id));
        let _ = writeln!(s, "state_key = {}", hex(&c.state_key));
        let _ = writeln!(s, "wrap_nonce_out = {}", hex(&c.wrap_nonce));
        let _ = writeln!(s, "wrap_nonce_in = {}", hex(&wrap_nonce_in(&c)));
        let _ = writeln!(s, "key_env_out = {}", hex(&b.key_env_out));
        let _ = writeln!(s, "key_env_in = {}", hex(&b.key_env_in));
        let _ = writeln!(
            s,
            "op_id[manifest,gen0,resend0] = {}",
            hex(&op_id(&c.object_id, -1, 0, 0))
        );
        let _ = writeln!(
            s,
            "op_id[0,gen1,resend2] = {}",
            hex(&op_id(&c.object_id, 0, 1, 2))
        );
        let _ = writeln!(s);
    }
    s
}
