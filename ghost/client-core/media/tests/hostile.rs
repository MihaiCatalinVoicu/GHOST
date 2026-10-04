//! Hostile inputs for the sniffer, the JPEG walker and the fMP4 walker (design §15.1, §15.2 item 6,
//! §22.2 row 16): deeply nested boxes, huge declared sizes, zero sizes, overlapping boxes, 32-bit
//! overflow, truncation at every offset, and seeded random bytes. Every one is refused with a typed
//! code, quickly, without a panic; nothing allocates more than the input's own bounds.
#![allow(clippy::disallowed_methods)]

mod support;

use std::time::Instant;

use ghost_client_media::consts::{MOOF_MAX_BYTES, MOOV_MAX_BYTES};
use ghost_client_media::fmp4::{self, Fmp4Checker};
use ghost_client_media::jpeg::{self, JpegChecker};
use ghost_client_media::{sniff, Code};
use support::*;

fn bx(typ: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut v = ((body.len() + 8) as u32).to_be_bytes().to_vec();
    v.extend_from_slice(typ);
    v.extend_from_slice(body);
    v
}

fn refused(data: &[u8]) -> ghost_client_media::MediaError {
    fmp4::check(data).expect_err("refused")
}

fn head() -> Vec<u8> {
    let g = golden("api35-emulator/quad_land.fmp4");
    g[..top_boxes(&g)[2].0].to_vec()
}

#[test]
fn deeply_nested_boxes() {
    // 8 000 trak boxes, each inside the last, inside a moov of the largest allowed size.
    let ftyp = &golden("api35-emulator/quad_land.fmp4")[..28];
    let mut inner = Vec::new();
    for _ in 0..8_000 {
        inner = bx(b"trak", &inner);
    }
    let mut data = ftyp.to_vec();
    data.extend(bx(b"moov", &inner));
    let t = Instant::now();
    let e = refused(&data);
    assert_eq!(e.code(), Code::NonCanonical);
    assert!(t.elapsed().as_secs() < 2);
    // Deep nesting past the moov bound is refused at its header, before any byte is buffered.
    let mut deeper = Vec::new();
    for _ in 0..9_000 {
        deeper = bx(b"trak", &deeper);
    }
    let mut data = ftyp.to_vec();
    data.extend(bx(b"moov", &deeper));
    assert!(refused(&data).rule().contains("a moov above 64 KiB"));
}

#[test]
fn huge_declared_sizes() {
    let h = head();
    let ftyp = &h[..28];
    for size in [u32::MAX, MOOV_MAX_BYTES + 1, 0x8000_0000] {
        let mut d = ftyp.to_vec();
        d.extend_from_slice(&size.to_be_bytes());
        d.extend_from_slice(b"moov");
        assert!(refused(&d).rule().contains("a moov above 64 KiB"), "{size}");
    }
    for size in [u32::MAX, MOOF_MAX_BYTES + 1] {
        let mut d = h.clone();
        d.extend_from_slice(&size.to_be_bytes());
        d.extend_from_slice(b"moof");
        assert!(
            refused(&d).rule().contains("a moof above 256 KiB"),
            "{size}"
        );
    }
    // A child whose size runs past its parent (overlapping boxes).
    let mut moov = h[28..].to_vec();
    let mvhd = 8;
    moov[mvhd..mvhd + 4].copy_from_slice(&0x7fff_fff0u32.to_be_bytes());
    let mut d = ftyp.to_vec();
    d.extend(moov);
    assert!(refused(&d).rule().contains("does not tile"));
    // The JPEG walker with a segment length past the end: refused at the end, nothing buffered
    // beyond the input.
    let j = [0xFF, 0xD8, 0xFF, 0xDB, 0xFF, 0xFF, 0x00];
    assert!(jpeg::check(&j).is_err());
}

#[test]
fn zero_and_tiny_sizes() {
    let h = head();
    for size in [0u32, 1, 7] {
        let mut d = h.clone();
        d.extend_from_slice(&size.to_be_bytes());
        d.extend_from_slice(b"moof");
        assert!(
            refused(&d).rule().contains("a box whose size is below 8"),
            "{size}"
        );
        // Inside the moov too.
        let mut m = h.clone();
        m[36..40].copy_from_slice(&size.to_be_bytes());
        assert_eq!(refused(&m).code(), Code::NonCanonical);
    }
    // JPEG segment lengths 0 and 1.
    for len in [0u8, 1] {
        assert!(jpeg::check(&[0xFF, 0xD8, 0xFF, 0xDB, 0x00, len, 0xFF, 0xD9]).is_err());
    }
}

#[test]
fn overflow_of_32_and_64_bit_sums() {
    let g = golden("api35-emulator/quad_land.fmp4");
    let boxes_top = top_boxes(&g);
    let moof = boxes_top[2].0;
    let tr = trafs(&g[moof..moof + boxes_top[2].1]);
    let vtrun = moof + tr[1].2;
    let vtfdt = moof + tr[1].1;
    // Video sample sizes near 2^32: their sum overflows u32 and must not wrap into a match.
    let mut d = g.clone();
    d[vtrun + 24..vtrun + 28].copy_from_slice(&0xffff_fff0u32.to_be_bytes());
    d[vtrun + 36..vtrun + 40].copy_from_slice(&0x0000_0020u32.to_be_bytes());
    assert_eq!(refused(&d).code(), Code::NonCanonical);
    // A tfdt near 2^64.
    let mut d = g.clone();
    d[vtfdt + 12..vtfdt + 20].copy_from_slice(&(u64::MAX - 5).to_be_bytes());
    assert_eq!(refused(&d).code(), Code::NonCanonical);
    // A data offset near 2^32.
    let mut d = g.clone();
    d[vtrun + 16..vtrun + 20].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(refused(&d).code(), Code::NonCanonical);
    // A sample count near 2^32 in a small trun.
    let mut d = g.clone();
    d[vtrun + 12..vtrun + 16].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(refused(&d).code(), Code::NonCanonical);
    // Durations whose sum passes VIDEO_MAX_MS.
    let mut d = g.clone();
    for s in 0..4 {
        d[vtrun + 20 + 12 * s..vtrun + 24 + 12 * s].copy_from_slice(&0x7fff_ffffu32.to_be_bytes());
    }
    assert_eq!(refused(&d).code(), Code::NonCanonical);
}

#[test]
fn truncation_at_every_offset() {
    // Every prefix of the small goldens and of every JPEG golden is refused, but the whole file.
    let mut fmp4_cases = vec![
        golden("api35-emulator/quad_land.fmp4"),
        golden("api29-emulator/quad_rot90.fmp4"),
    ];
    fmp4_cases.push(fmp4_of_len(140_000));
    for data in fmp4_cases {
        let mut c = Fmp4Checker::new();
        for (i, b) in data.iter().enumerate() {
            assert!(c.finish().is_err(), "a {i}-byte prefix accepted");
            c.feed(&[*b]).expect("the golden's bytes");
        }
        c.finish().expect("the whole file");
    }
    for (name, data) in goldens(".jpg") {
        let mut c = JpegChecker::new();
        for (i, b) in data.iter().enumerate() {
            assert!(c.finish().is_err(), "{name}: a {i}-byte prefix accepted");
            c.feed(&[*b]).expect("the golden's bytes");
        }
        c.finish().expect("the whole file");
    }
}

/// §15.1: "seeded decoder and walker property runs of 10⁶ inputs per CI run". The count is
/// `GHOST_MEDIA_RANDOM_INPUTS` (default 10⁶), the seed `GHOST_MEDIA_RANDOM_SEED` (default 7; a
/// failure names its input's index).
#[test]
fn seeded_random_bytes_are_refused_quickly() {
    let inputs: usize = std::env::var("GHOST_MEDIA_RANDOM_INPUTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000);
    let seed: u64 = std::env::var("GHOST_MEDIA_RANDOM_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7);
    let mut rng = Seeded::new(seed);
    let ftyp_moov = head();
    let t = Instant::now();
    for i in 0..inputs {
        let len = rng.below(if i % 100 == 0 { 70_000 } else { 300 });
        let mut data = rng.bytes(len);
        match i % 4 {
            0 => {}
            1 => {
                // A valid prefix, then noise.
                let cut = rng.below(ftyp_moov.len());
                data.splice(0..0, ftyp_moov[..cut].iter().copied());
            }
            2 => {
                data.splice(0..0, [0xFF, 0xD8, 0xFF]);
            }
            _ => {
                data.splice(0..0, *b"\0\0\0\x1cftypisom");
            }
        }
        assert!(fmp4::check(&data).is_err());
        let j = jpeg::check(&data);
        let c = jpeg::canonicalize(&data);
        assert_eq!(
            j.is_ok(),
            c.as_ref().map(|c| **c == data).unwrap_or(false),
            "check and canonicalize agree"
        );
        let _ = sniff(&data);
    }
    eprintln!(
        "{inputs} seeded random inputs (seed {seed}) refused in {:?}",
        t.elapsed()
    );
}

#[test]
fn hostile_jpeg_segments() {
    let base = grey_jpeg(320, 208);
    let sos = base.windows(2).position(|w| w == [0xFF, 0xDA]).unwrap();
    let cases: Vec<Vec<u8>> = vec![
        // A DHT whose counts claim more codes than the segment holds.
        [
            &base[..sos],
            &[0xFF, 0xC4, 0x00, 0x13, 0x00][..],
            &[0xFF; 16],
            &base[sos..],
        ]
        .concat(),
        // A SOF0 of 255 components.
        [&[
            0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x08, 0x08, 0x00, 0x10, 0x00, 0x10, 0xFF,
        ][..]]
        .concat(),
        // A width of zero.
        [&[
            0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x10, 0x00, 0x00, 0x01, 0x01, 0x11,
            0x00,
        ][..]]
        .concat(),
        // Entropy data that ends with 0xFF.
        [&base[..base.len() - 2], &[0xFF][..]].concat(),
        // Restart markers out of order with a DRI.
        {
            let mut v = jpeg_of_len(512, 512, 2_000);
            let at = v.windows(2).position(|w| w == [0xFF, 0xD0]).unwrap();
            v[at + 1] = 0xD3;
            v
        },
        // A 65 535-byte COM in check mode (refused) — canonicalize drops it.
        [
            &base[..2],
            &[0xFF, 0xFE, 0xFF, 0xFF][..],
            &vec![0x41; 65_533],
            &base[2..],
        ]
        .concat(),
    ];
    for (i, c) in cases.iter().enumerate() {
        assert_eq!(
            jpeg::check(c).map(|_| ()).map_err(|e| e.code()),
            Err(Code::NonCanonical),
            "case {i}"
        );
    }
    assert_eq!(*jpeg::canonicalize(&cases[5]).expect("COM dropped"), base);
}

#[test]
fn the_sniffer_on_every_prefix_and_byte() {
    for (_, data) in goldens("").into_iter().take(28) {
        let head = &data[..64.min(data.len())];
        for n in 0..=head.len() {
            let _ = sniff(&head[..n]);
        }
        for at in 0..head.len() {
            for v in [0x00, 0xFF, head[at] ^ 0x01] {
                let mut m = head.to_vec();
                m[at] = v;
                let _ = sniff(&m);
            }
        }
    }
}
