//! The committed goldens of Media3 1.11.1 (design §8.3, §15.2 item 6, G-M8): every file is accepted
//! by the walkers byte for byte, the `mfra` the sealer builds from a golden's fragments is the
//! golden's own, and every golden seals and reads back to itself.
#![allow(clippy::disallowed_methods)]

mod support;

use ghost_client_media::fmp4;
use ghost_client_media::jpeg;
use ghost_client_media::keys::sha256;
use ghost_client_media::{Expected, FileKey, MediaKind, ObjectId, Reader, Sealer, SizeClass};
use support::*;

#[test]
fn the_sums_are_the_committed_ones() {
    let sums = std::fs::read_to_string(goldens_dir().join("SHA256SUMS")).expect("SHA256SUMS");
    let mut n = 0;
    for line in sums.lines().filter(|l| !l.trim().is_empty()) {
        let (sum, name) = line.split_once(" *").expect("sum *name");
        assert_eq!(hex::encode(sha256(&golden(name))), sum, "{name}");
        n += 1;
    }
    assert_eq!(n, 28);
}

#[test]
fn every_fmp4_golden_is_canonical() {
    for (name, data) in goldens(".fmp4") {
        let info = fmp4::check(&data).unwrap_or_else(|e| panic!("{name}: {e}"));
        let want_rotation = if name.contains("rot90") || name.contains("port") {
            90
        } else if name.contains("rot180") {
            180
        } else if name.contains("rot270") {
            270
        } else {
            0
        };
        assert_eq!(info.rotation, want_rotation, "{name}");
        let displayed = if want_rotation % 180 == 90 {
            (720, 1280)
        } else {
            (1280, 720)
        };
        assert_eq!((info.width, info.height), displayed, "{name}");
        assert_eq!(info.colour, (5, 1, 6), "{name}: the BT.601 label (S0-13)");
        assert_eq!(
            info.profile_idc, 66,
            "{name}: the emulators' Baseline encoders"
        );
        assert_eq!(info.video_track, 2, "{name}: Transformer adds audio first");
        let api29 = name.starts_with("api29");
        assert_eq!(
            info.moofs.len() == 1,
            api29,
            "{name}: API 29 writes one IDR per 1 000 frames"
        );
        // The duration: the video track's summed trun durations, rounded down (§3.5).
        let expect_ms = if name.contains("land1080p60") {
            6000
        } else {
            3966
        };
        assert_eq!(info.duration_ms, expect_ms, "{name}");
    }
}

#[test]
fn the_sealer_builds_each_goldens_mfra() {
    for (name, data) in goldens(".fmp4") {
        let stream = without_mfra(&data);
        let mfra = &data[stream.len()..];
        let info_reader = fmp4::check(&data).expect("canonical");
        let built = fmp4::build_mfra(info_reader.video_track, &info_reader.moofs);
        assert_eq!(built, mfra, "{name}: the mfra GHOST builds is the golden's");
    }
}

#[test]
fn every_jpeg_golden_is_canonical_and_a_fixed_point() {
    for (name, data) in goldens(".jpg") {
        let info = jpeg::check(&data).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(info.components, 3, "{name}");
        let long = info.width.max(info.height);
        assert!([512, 1024, 2048].contains(&long), "{name}: {info:?}");
        assert_eq!(info.width.min(info.height) % 16, 0, "{name}: {info:?}");
        assert_eq!(
            jpeg::canonicalize(&data).expect("canonical"),
            data,
            "{name}"
        );
    }
}

/// Seals `content` (a video's without its `mfra`) in pieces of `piece` bytes and reads it back.
fn seal_and_read(kind: MediaKind, stream: &[u8], piece: usize, seed: u8) -> Vec<u8> {
    let key = FileKey::from_bytes([seed; 32]);
    let id = ObjectId::from_bytes([seed ^ 0x5a; 16]);
    let mut sealer = Sealer::begin(key.clone(), id, kind, false, SizeClass::LARGEST);
    let mut chunks = Vec::new();
    for p in stream.chunks(piece) {
        chunks.extend(sealer.append(p).expect("append"));
    }
    let sealed = sealer.finish(&grey_jpeg(320, 176)).expect("finish");
    chunks.extend(sealed.chunks.iter().cloned());
    let expected = Expected {
        object_id: id,
        kind,
        view_once: false,
        class: sealed.manifest.fields.class,
        manifest_hash: sealed.manifest_hash,
    };
    let mut reader = Reader::open(&key, &expected, &sealed.manifest_blob).expect("open");
    assert_eq!(chunks.len() as u32, reader.chunk_count());
    let mut content = Vec::new();
    let mut out = vec![0u8; ghost_client_media::consts::CHUNK_PT];
    for c in &chunks {
        reader
            .validate_chunk(c.index, &c.ciphertext)
            .expect("validate");
        let n = reader
            .read_chunk(c.index, &c.ciphertext, &mut out)
            .expect("read");
        content.extend_from_slice(&out[..n]);
    }
    let walked = reader.validate_finish().expect("finish");
    let f = sealed.manifest.fields;
    assert_eq!(
        (walked.width, walked.height, walked.duration_ms),
        (f.width, f.height, f.duration_ms)
    );
    content
}

#[test]
fn every_golden_seals_and_reads_back_to_itself() {
    for (i, (name, data)) in goldens(".fmp4").into_iter().enumerate() {
        let content = seal_and_read(
            MediaKind::Video,
            &without_mfra(&data),
            4096 + 977 * i,
            i as u8,
        );
        assert_eq!(content, data, "{name}");
    }
    for (i, (name, data)) in goldens(".jpg").into_iter().enumerate() {
        let content = seal_and_read(MediaKind::Image, &data, 1 + 1013 * i, 0x40 + i as u8);
        assert_eq!(content, data, "{name}");
    }
}
