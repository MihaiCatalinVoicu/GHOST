//! Measurements of design §15.1 ("≤ 1 ms per 256 KiB chunk, [I], measured in S1") and §13.1's
//! throughput row, on the host: seal and open a class-10 object (201 chunks, 52 428 800 bytes of
//! canonical content) and a class-0 image. Ignored by default (timings are machine-dependent); run
//! `cargo test --release -p ghost-client-media --test timing -- --ignored --nocapture`.
#![allow(clippy::disallowed_methods)]

mod support;

use std::time::Instant;

use ghost_client_media::consts::{CHUNK_PT, MAX_CONTENT};
use ghost_client_media::keys::sha256;
use ghost_client_media::{fmp4, jpeg};
use ghost_client_media::{Expected, FileKey, MediaKind, ObjectId, Reader, Sealer, SizeClass};
use support::*;

#[test]
#[ignore = "a measurement, not a check"]
fn seal_and_open_throughput() {
    for (kind, data) in [
        (MediaKind::Video, fmp4_of_len(MAX_CONTENT as usize)),
        (MediaKind::Image, jpeg_of_len(2048, 1536, 1_000_000)),
    ] {
        let input = match kind {
            MediaKind::Video => without_mfra(&data),
            MediaKind::Image => data.clone(),
        };
        // The walk alone (the sealer walks every byte again before it seals it).
        let walk = Instant::now();
        match kind {
            MediaKind::Video => {
                fmp4::check(&data).expect("canonical");
            }
            MediaKind::Image => {
                jpeg::check(&data).expect("canonical");
            }
        }
        let walk = walk.elapsed();
        let key = FileKey::from_bytes([9; 32]);
        let id = ObjectId::from_bytes([8; 16]);
        let t = Instant::now();
        let mut s = Sealer::begin(key.clone(), id, kind, false, SizeClass::LARGEST);
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        for piece in input.chunks(CHUNK_PT) {
            chunks.extend(
                s.append(piece)
                    .expect("append")
                    .into_iter()
                    .map(|c| c.ciphertext),
            );
        }
        let sealed = s.finish(&[]).expect("finish");
        chunks.extend(sealed.chunks.iter().map(|c| c.ciphertext.clone()));
        let seal = t.elapsed();
        // The crate's tests always build the nonce registry (a dev-dependency on the crate with
        // `nonce-registry`), which hashes every sealed chunk once more; a shipped build has no
        // registry, so that hash is timed here and taken off the seal figure.
        let registry = {
            let block = vec![0x5a_u8; CHUNK_PT];
            let t = Instant::now();
            for _ in 0..chunks.len() {
                std::hint::black_box(sha256(std::hint::black_box(&block)));
            }
            t.elapsed()
        };
        let shipped_seal = seal.saturating_sub(registry);
        let e = Expected {
            object_id: id,
            kind,
            view_once: false,
            class: sealed.manifest.fields.class,
            manifest_hash: sealed.manifest_hash,
        };
        let t = Instant::now();
        let mut r = Reader::open(&key, &e, &sealed.manifest_blob).expect("open");
        for (i, c) in chunks.iter().enumerate() {
            r.validate_chunk(i as u32, c).expect("validate");
        }
        r.validate_finish().expect("finish");
        let validate = t.elapsed();
        let t = Instant::now();
        let mut out = vec![0u8; CHUNK_PT];
        for (i, c) in chunks.iter().enumerate() {
            r.read_chunk(i as u32, c, &mut out).expect("read");
        }
        let read = t.elapsed();
        let n = chunks.len() as f64;
        let mb = data.len() as f64 / 1e6;
        eprintln!(
            "{kind:?}: {} B, class {}, {} chunks: walk {:?}; seal {:?} ({:.3} ms/chunk, {:.0} MB/s with walk and hashes; {:.3} ms/chunk without the test registry's hash); validate {:?} ({:.3} ms/chunk); read {:?} ({:.3} ms/chunk, {:.0} MB/s)",
            data.len(),
            sealed.manifest.fields.class.code(),
            chunks.len(),
            walk,
            seal,
            seal.as_secs_f64() * 1e3 / n,
            mb / seal.as_secs_f64(),
            shipped_seal.as_secs_f64() * 1e3 / n,
            validate,
            validate.as_secs_f64() * 1e3 / n,
            read,
            read.as_secs_f64() * 1e3 / n,
            mb / read.as_secs_f64(),
        );
    }
}
