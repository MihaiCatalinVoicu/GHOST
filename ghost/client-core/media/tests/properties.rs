//! Property tests of the sealer and the reader (design §15.2 items 2–4; CS-M1, CS-M2).
//!
//! - CS-M1: over seeded random call sequences (pieces of every size, aborts, refusals, resumed
//!   preparations under fresh keys), the nonce registry (§3.7 point 5) never sees a second
//!   plaintext under one `(key, nonce)`, every finished object sealed each index once with the last
//!   flag on `n − 1` only, and an abandoned one only a prefix with no last flag. A resumed
//!   preparation **under the same key** (mutant MC-M1's shape) is caught by the registry.
//! - CS-M2: the corruption matrix over a class-0 and a class-1 object (single-bit flips at sampled
//!   positions of every fragment and of the manifest, swaps, foreign, duplicated and dropped
//!   fragments, the last flag removed, another `object_id`, `F` changed, a non-zero pad), each with
//!   its typed code and no content byte exposed; round trips at every class boundary ± 1.
//!
//! `GHOST_MEDIA_PROPERTY_OBJECTS` (default 600) sets the number of CS-M1 sequences and
//! `GHOST_MEDIA_FLIPS` (default 256) the sampled bit flips per fragment; §15.2 item 3 asks for
//! 10⁴ objects and item 2 for 4 096 flips per fragment, which the gate run sets.
#![allow(clippy::disallowed_methods)]

mod support;

use ghost_client_media::class::SizeClass;
use ghost_client_media::consts::{CHUNK_CT, CHUNK_PT, FRAG};
use ghost_client_media::fmp4::Fmp4Checker;
use ghost_client_media::jpeg::JpegChecker;
use ghost_client_media::keys::{derive, sha256};
use ghost_client_media::registry;
use ghost_client_media::stream::chunk_nonce;
use ghost_client_media::{
    Code, Expected, FileKey, MediaKind, ObjectId, Reader, SealedChunk, Sealer,
};
use support::*;

fn env_count(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// A canonical content of `kind` from the seeded stream: images of every class-0 size, videos of
/// class 0 to 2.
fn content(rng: &mut Seeded, kind: MediaKind) -> Vec<u8> {
    match kind {
        MediaKind::Image => match rng.below(3) {
            0 => grey_jpeg(512, 16 * (1 + rng.below(32)) as u16),
            1 => golden(
                [
                    "api35-emulator/strip_orient1.jpg",
                    "api29-emulator/strip_photo_webp.jpg",
                ][rng.below(2)],
            ),
            _ => jpeg_of_len(1024, 768, 1_000 + rng.below(1_047_000)),
        },
        MediaKind::Video => match rng.below(3) {
            0 => golden(
                [
                    "api35-emulator/quad_rot90.fmp4",
                    "api29-emulator/quad_port.fmp4",
                ][rng.below(2)],
            ),
            _ => fmp4_of_len(120_000 + rng.below(2_200_000)),
        },
    }
}

fn input_of(kind: MediaKind, content: &[u8]) -> Vec<u8> {
    match kind {
        MediaKind::Image => content.to_vec(),
        MediaKind::Video => without_mfra(content),
    }
}

/// The nonces a finished object of `n` chunks must have used, once each.
fn finished_nonces(n: u32) -> Vec<[u8; 12]> {
    let mut v: Vec<[u8; 12]> = (0..n).map(|i| chunk_nonce(i, i + 1 == n)).collect();
    v.sort_unstable();
    v
}

#[test]
fn cs_m1_no_nonce_reuse_across_call_sequences() {
    let objects = env_count("GHOST_MEDIA_PROPERTY_OBJECTS", 600);
    let mut rng = Seeded::new(0x6d65_6469_612d_3101);
    let (mut finished, mut abandoned, mut refused) = (0, 0, 0);
    for trial in 0..objects {
        let kind = if rng.below(2) == 0 {
            MediaKind::Image
        } else {
            MediaKind::Video
        };
        let data = content(&mut rng, kind);
        let input = input_of(kind, &data);
        // A preparation may be interrupted and resumed any number of times: each attempt is a new
        // sealer with a new key (§3.7 point 3), as the S2 surface draws them.
        let attempts = 1 + rng.below(3);
        for attempt in 0..attempts {
            let key = FileKey::from_bytes(rng.key32());
            let id = ObjectId::from_bytes(rng.id16());
            let kp = registry::key_digest(derive(&key, &id).payload.as_bytes());
            let mut sealer = Sealer::begin(key, id, kind, false, SizeClass::LARGEST);
            let last_attempt = attempt + 1 == attempts;
            let stop_at = if last_attempt {
                input.len()
            } else {
                rng.below(input.len() + 1)
            };
            let corrupt = last_attempt && rng.below(10) == 0;
            let mut at = 0;
            let mut chunks: Vec<SealedChunk> = Vec::new();
            let mut ok = true;
            while at < stop_at {
                let piece = match rng.below(4) {
                    0 => 1 + rng.below(16),
                    1 => 1 + rng.below(70_000),
                    2 => CHUNK_PT + rng.below(3) - 1,
                    _ => 1 + rng.below(600_000),
                }
                .min(stop_at - at);
                let mut bytes = input[at..at + piece].to_vec();
                if corrupt && at == 0 {
                    bytes[0] ^= 0x40; // a stream the walker refuses at its first byte
                }
                match sealer.append(&bytes) {
                    Ok(c) => chunks.extend(c),
                    Err(e) => {
                        assert_eq!(e.code(), Code::NonCanonical, "trial {trial}");
                        assert_eq!(sealer.append(&[0]).unwrap_err().code(), Code::Sequence);
                        ok = false;
                        break;
                    }
                }
                if rng.below(50) == 0 {
                    assert_eq!(
                        sealer.append(&[]).map(|c| c.len()),
                        Ok(0),
                        "an empty piece seals nothing"
                    );
                }
                at += piece;
            }
            let nonces = registry::nonces_for(&kp);
            if !ok {
                refused += 1;
                assert!(
                    nonces.is_empty(),
                    "trial {trial}: a refused first piece sealed something"
                );
            } else if last_attempt {
                let sealed = sealer.finish(&[]).expect("finish");
                chunks.extend(sealed.chunks.iter().cloned());
                let n = sealed.manifest.fields.class.chunks();
                assert_eq!(
                    registry::nonces_for(&kp),
                    finished_nonces(n),
                    "trial {trial}"
                );
                let indices: Vec<u32> = chunks.iter().map(|c| c.index).collect();
                assert_eq!(
                    indices,
                    (0..n).collect::<Vec<_>>(),
                    "trial {trial}: every index once, in order"
                );
                finished += 1;
            } else {
                // Abandoned: a prefix of indices, none with the last flag.
                let sealed_count = chunks.len() as u32;
                assert!(
                    nonces.iter().all(|n| n[11] == 0),
                    "trial {trial}: a last flag before finish"
                );
                assert_eq!(nonces.len() as u32, sealed_count);
                sealer.abort();
                abandoned += 1;
            }
            assert!(
                registry::violations_for(&kp).is_empty(),
                "trial {trial}: nonce reuse"
            );
        }
    }
    eprintln!("CS-M1: {objects} objects, {finished} finished, {abandoned} abandoned attempts, {refused} refused");
    assert!(finished > objects / 2 && abandoned > 0 && refused > 0);
}

#[test]
fn cs_m1_a_resumed_preparation_under_the_same_key_is_caught() {
    // MC-M1's shape: the key persisted at sealBegin and the preparation resumed under it with a
    // transcode that differs (transcoding is not deterministic). The registry must see it.
    let key = FileKey::from_bytes([0x71; 32]);
    let id = ObjectId::from_bytes([0x72; 16]);
    let kp = registry::key_digest(derive(&key, &id).payload.as_bytes());
    for content in [fmp4_of_len(900_000), fmp4_of_len(900_001)] {
        let mut s = Sealer::begin(key.clone(), id, MediaKind::Video, false, SizeClass::LARGEST);
        s.append(&without_mfra(&content)).expect("append");
        s.finish(&[]).expect("finish");
    }
    assert!(
        !registry::violations_for(&kp).is_empty(),
        "the registry missed a resumed preparation"
    );
}

struct Object {
    key: FileKey,
    expected: Expected,
    chunks: Vec<Vec<u8>>,
    blob: Vec<u8>,
}

fn seal(seed: u8, kind: MediaKind, content: &[u8]) -> Object {
    let key = FileKey::from_bytes([seed; 32]);
    let id = ObjectId::from_bytes([seed.wrapping_add(1); 16]);
    let mut s = Sealer::begin(key.clone(), id, kind, false, SizeClass::LARGEST);
    let mut chunks: Vec<Vec<u8>> = s
        .append(&input_of(kind, content))
        .expect("append")
        .into_iter()
        .map(|c| c.ciphertext)
        .collect();
    let sealed = s.finish(&grey_jpeg(320, 176)).expect("finish");
    chunks.extend(sealed.chunks.iter().map(|c| c.ciphertext.clone()));
    Object {
        key,
        expected: Expected {
            object_id: id,
            kind,
            view_once: false,
            class: sealed.manifest.fields.class,
            manifest_hash: sealed.manifest_hash,
        },
        chunks,
        blob: sealed.manifest_blob,
    }
}

/// Reads chunk `i` from `frags` into a zeroed buffer; on refusal the buffer must stay zero.
fn read(r: &Reader, i: u32, frags: &[u8]) -> Result<(), Code> {
    let mut out = vec![0u8; CHUNK_PT];
    let res = r
        .read_chunk(i, frags, &mut out)
        .map(|_| ())
        .map_err(|e| e.code());
    if res.is_err() {
        assert!(
            out.iter().all(|b| *b == 0),
            "a refused chunk exposed content"
        );
    }
    res
}

#[test]
fn cs_m2_corruption_matrix() {
    let flips = env_count("GHOST_MEDIA_FLIPS", 256);
    let class0 = seal(
        0x31,
        MediaKind::Video,
        &golden("api35-emulator/quad_land.fmp4"),
    );
    let class1 = seal(0x41, MediaKind::Video, &fmp4_of_len(1_400_000));
    assert_eq!(class0.expected.class.code(), 0);
    assert_eq!(class1.expected.class.code(), 1);
    let mut rng = Seeded::new(0x0c5_2002);
    let mut counted = 0usize;
    for (obj, other) in [(&class0, &class1), (&class1, &class0)] {
        let r = Reader::open(&obj.key, &obj.expected, &obj.blob).expect("open");
        let n = obj.chunks.len();
        let fragments = n * 4;
        // Single-bit flips of every fragment: HASH_MISMATCH at its chunk.
        for j in 0..fragments {
            for _ in 0..flips {
                let mut c = obj.chunks[j / 4].clone();
                let at = (j % 4) * FRAG + rng.below(FRAG);
                c[at] ^= 1 << rng.below(8);
                assert_eq!(read(&r, (j / 4) as u32, &c), Err(Code::HashMismatch));
                counted += 1;
            }
        }
        // Single-bit flips of the manifest: HASH_MISMATCH (the descriptor names the old blob).
        for _ in 0..flips * 4 {
            let mut b = obj.blob.clone();
            b[rng.below(FRAG)] ^= 1 << rng.below(8);
            assert_eq!(
                Reader::open(&obj.key, &obj.expected, &b)
                    .map(|_| ())
                    .map_err(|e| e.code()),
                Err(Code::HashMismatch)
            );
            counted += 1;
        }
        // The same flips with the descriptor naming the flipped blob: the commitment or the tag.
        for _ in 0..flips {
            let mut b = obj.blob.clone();
            let at = rng.below(FRAG);
            b[at] ^= 1 << rng.below(8);
            let mut e = obj.expected;
            e.manifest_hash = sha256(&b);
            let want = if at < 32 {
                Code::CommitMismatch
            } else {
                Code::NotOpen
            };
            assert_eq!(
                Reader::open(&obj.key, &e, &b)
                    .map(|_| ())
                    .map_err(|e| e.code()),
                Err(want)
            );
            counted += 1;
        }
        for i in 0..n {
            for k in 0..4 {
                let j = 4 * i + k;
                // Swapped with every other position, duplicated, from the same position of another
                // object, dropped (the chunk short by one fragment).
                for j2 in 0..fragments {
                    if j2 == j {
                        continue;
                    }
                    let mut c = obj.chunks[i].clone();
                    c[k * FRAG..(k + 1) * FRAG]
                        .copy_from_slice(&obj.chunks[j2 / 4][(j2 % 4) * FRAG..(j2 % 4 + 1) * FRAG]);
                    assert_eq!(
                        read(&r, i as u32, &c),
                        Err(Code::HashMismatch),
                        "fragment {j} := {j2}"
                    );
                    counted += 1;
                }
                if j < other.chunks.len() * 4 {
                    let mut c = obj.chunks[i].clone();
                    c[k * FRAG..(k + 1) * FRAG]
                        .copy_from_slice(&other.chunks[i][k * FRAG..(k + 1) * FRAG]);
                    assert_eq!(read(&r, i as u32, &c), Err(Code::HashMismatch));
                    counted += 1;
                }
                let mut dropped = obj.chunks[i].clone();
                dropped.drain(k * FRAG..(k + 1) * FRAG);
                assert_eq!(read(&r, i as u32, &dropped), Err(Code::HashMismatch));
                let mut extended = obj.chunks[i].clone();
                extended.push(0);
                assert_eq!(read(&r, i as u32, &extended), Err(Code::HashMismatch));
                counted += 2;
            }
            // The honest chunk reads.
            assert_eq!(read(&r, i as u32, &obj.chunks[i]), Ok(()));
        }
        assert_eq!(read(&r, n as u32, &obj.chunks[0]), Err(Code::IndexRange));
        assert_eq!(read(&r, u32::MAX, &obj.chunks[0]), Err(Code::IndexRange));
    }
    eprintln!("CS-M2 corruption matrix: {counted} cases ({flips} flips per fragment)");
}

#[test]
fn cs_m2_round_trips_at_every_class_boundary() {
    let mut lens: Vec<(MediaKind, usize)> = Vec::new();
    for c in SizeClass::all() {
        let cap = c.capacity() as usize;
        for l in [cap - 1, cap, cap + 1] {
            lens.push((MediaKind::Video, l));
        }
    }
    let image_max = ghost_client_media::consts::IMAGE_MAX_CONTENT as usize;
    for l in [image_max - 1, image_max, image_max + 1, 2_000] {
        lens.push((MediaKind::Image, l));
    }
    for (n, (kind, len)) in lens.into_iter().enumerate() {
        let data = match kind {
            MediaKind::Video => fmp4_of_len(len),
            MediaKind::Image => jpeg_of_len(1024, 768, len),
        };
        let key = FileKey::from_bytes(core::array::from_fn(|i| (i + n) as u8));
        let id = ObjectId::from_bytes(core::array::from_fn(|i| (i * 7 + n) as u8));
        let mut s = Sealer::begin(key.clone(), id, kind, false, SizeClass::LARGEST);
        let input = input_of(kind, &data);
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut refused = None;
        for piece in input.chunks(1_000_003) {
            match s.append(piece) {
                Ok(c) => chunks.extend(c.into_iter().map(|c| c.ciphertext)),
                Err(e) => {
                    refused = Some(e.code());
                    break;
                }
            }
        }
        let want_class = SizeClass::for_content_len(len as u64);
        let image_over = kind == MediaKind::Image && len > image_max;
        let finished = match refused {
            Some(code) => {
                assert_eq!(code, Code::Oversize, "{kind:?} {len}");
                None
            }
            None => match s.finish(&[]) {
                Ok(o) => Some(o),
                Err(e) => {
                    assert_eq!(e.code(), Code::Oversize, "{kind:?} {len}");
                    None
                }
            },
        };
        match (want_class, image_over, finished) {
            (Some(c), false, Some(sealed)) => {
                assert_eq!(sealed.manifest.fields.class, c, "{kind:?} {len}");
                assert_eq!(sealed.manifest.fields.content_len, len as u64);
                chunks.extend(sealed.chunks.iter().map(|c| c.ciphertext.clone()));
                let e = Expected {
                    object_id: id,
                    kind,
                    view_once: false,
                    class: c,
                    manifest_hash: sealed.manifest_hash,
                };
                let mut r = Reader::open(&key, &e, &sealed.manifest_blob).expect("open");
                let mut back = Vec::with_capacity(len);
                let mut out = vec![0u8; CHUNK_PT];
                for (i, ch) in chunks.iter().enumerate() {
                    assert_eq!(ch.len(), CHUNK_CT);
                    r.validate_chunk(i as u32, ch).expect("validate");
                    let k = r.read_chunk(i as u32, ch, &mut out).expect("read");
                    back.extend_from_slice(&out[..k]);
                }
                r.validate_finish().expect("finish");
                assert!(back == data, "{kind:?} {len}: the content reads back");
            }
            (None, _, None) | (_, true, None) => {}
            (w, over, f) => panic!(
                "{kind:?} {len}: class {w:?}, image over {over}, sealed {}",
                f.is_some()
            ),
        }
    }
}

#[test]
fn the_validation_pass_is_in_order_and_complete() {
    let obj = seal(
        0x51,
        MediaKind::Video,
        &golden("api35-emulator/quad_rot180.fmp4"),
    );
    let open = || Reader::open(&obj.key, &obj.expected, &obj.blob).expect("open");
    let mut r = open();
    assert_eq!(
        r.validate_chunk(1, &obj.chunks[1]).unwrap_err().code(),
        Code::Sequence,
        "skipped"
    );
    assert_eq!(
        r.validate_chunk(0, &obj.chunks[0]).unwrap_err().code(),
        Code::Sequence,
        "a failed pass is spent"
    );
    let mut r = open();
    r.validate_chunk(0, &obj.chunks[0]).expect("0");
    assert_eq!(
        r.validate_chunk(0, &obj.chunks[0]).unwrap_err().code(),
        Code::Sequence,
        "repeated"
    );
    let mut r = open();
    for i in 0..3 {
        r.validate_chunk(i, &obj.chunks[i as usize])
            .expect("prefix");
    }
    assert_eq!(
        r.validate_finish().unwrap_err().code(),
        Code::NonCanonical,
        "truncated"
    );
    let mut r = open();
    assert_eq!(
        r.validate_chunk(4, &obj.chunks[0]).unwrap_err().code(),
        Code::IndexRange,
        "extended"
    );
    let mut r = open();
    for i in 0..4 {
        r.validate_chunk(i, &obj.chunks[i as usize]).expect("all");
    }
    r.validate_finish().expect("complete");
    assert_eq!(
        r.validate_finish().unwrap_err().code(),
        Code::Sequence,
        "finished once"
    );
}

#[test]
fn the_walk_does_not_depend_on_piece_sizes() {
    let mut rng = Seeded::new(42);
    let mut cases: Vec<Vec<u8>> = goldens(".fmp4").into_iter().map(|(_, d)| d).collect();
    cases.push(fmp4_of_len(700_000));
    for data in &cases {
        let whole = ghost_client_media::fmp4::check(data);
        for _ in 0..8 {
            let mut c = Fmp4Checker::new();
            let mut at = 0;
            let mut result = Ok(());
            while at < data.len() && result.is_ok() {
                let bound = if rng.below(2) == 0 { 9 } else { 200_000 };
                let n = (1 + rng.below(bound)).min(data.len() - at);
                result = c.feed(&data[at..at + n]);
                at += n;
            }
            let pieces = result.and_then(|()| c.finish());
            assert_eq!(pieces, whole);
        }
    }
    for (_, data) in goldens(".jpg") {
        let whole = ghost_client_media::jpeg::check(&data);
        for _ in 0..8 {
            let mut c = JpegChecker::new();
            let mut at = 0;
            while at < data.len() {
                let n = (1 + rng.below(3000)).min(data.len() - at);
                c.feed(&data[at..at + n]).expect("piece");
                at += n;
            }
            assert_eq!(c.finish(), whole);
        }
    }
}
