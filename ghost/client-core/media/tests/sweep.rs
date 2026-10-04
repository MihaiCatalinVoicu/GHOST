//! The no-panic sweep (design §15.1: "never panics, never over-reads, NON_CANONICAL or OK only"; the
//! S1 brief): every prefix and single-byte mutations at every offset of the goldens, and of the
//! vector inputs (descriptors, manifest plaintexts, sniffer and JPEG inputs), through every parser
//! that reads them. A panic fails the test (the harness reports it); every refusal is a typed code.
//!
//! A mutation at offset k is walked from a copy of the walker after k bytes; when the copy's state
//! after the mutated byte equals the original's after the original byte, the rest of the walk is the
//! original's (already walked without a panic) and is skipped. Values per offset: x ^ 0xFF and
//! x ^ 0x01 (GHOST_MEDIA_SWEEP=full adds 0x00, 0xFF and x ^ 0x80); the 1080p60 goldens are swept at
//! every 7th offset unless GHOST_MEDIA_SWEEP=full.
#![allow(clippy::disallowed_methods)]

mod support;

use std::time::Instant;

use ghost_client_media::descriptor::Descriptor;
use ghost_client_media::fmp4::Fmp4Checker;
use ghost_client_media::jpeg::{self, JpegChecker};
use ghost_client_media::manifest::Manifest;
use ghost_client_media::{sniff, Code};
use support::replay::{honest, recipe, specs};
use support::*;

fn full() -> bool {
    std::env::var("GHOST_MEDIA_SWEEP").is_ok_and(|v| v == "full")
}

fn values(x: u8) -> Vec<u8> {
    let mut v = vec![x ^ 0xFF, x ^ 0x01];
    if full() {
        v.extend([0x00, 0xFF, x ^ 0x80]);
    }
    v.retain(|b| *b != x);
    v.sort_unstable();
    v.dedup();
    v
}

/// A streaming walker the sweep can drive.
trait Walk: Clone + PartialEq {
    fn feed(&mut self, data: &[u8]) -> Result<(), Code>;
    fn done(&self) -> Result<(), Code>;
}

impl Walk for Fmp4Checker {
    fn feed(&mut self, data: &[u8]) -> Result<(), Code> {
        Fmp4Checker::feed(self, data).map_err(|e| e.code())
    }
    fn done(&self) -> Result<(), Code> {
        self.finish().map(|_| ()).map_err(|e| e.code())
    }
}

impl Walk for JpegChecker {
    fn feed(&mut self, data: &[u8]) -> Result<(), Code> {
        JpegChecker::feed(self, data).map_err(|e| e.code())
    }
    fn done(&self) -> Result<(), Code> {
        self.finish().map(|_| ()).map_err(|e| e.code())
    }
}

/// Sweeps `data` (which `fresh` accepts whole): every prefix, and the mutations at every
/// `stride`-th offset. Returns (mutations walked, mutations skipped as identical futures).
fn sweep<W: Walk>(fresh: W, data: &[u8], stride: usize) -> (usize, usize) {
    let mut base = fresh;
    let (mut walked, mut skipped) = (0, 0);
    for k in 0..data.len() {
        assert!(base.done().is_err(), "a {k}-byte prefix accepted");
        let mut next = base.clone();
        next.feed(&data[k..k + 1]).expect("the original byte");
        if k % stride == 0 {
            for v in values(data[k]) {
                let mut m = base.clone();
                if m.feed(&[v]).is_err() {
                    continue;
                }
                if m == next {
                    skipped += 1;
                    continue;
                }
                walked += 1;
                let mut at = k + 1;
                while at < data.len() {
                    let n = (data.len() - at).min(65_536);
                    if m.feed(&data[at..at + n]).is_err() {
                        break;
                    }
                    at += n;
                }
                let r = m.done();
                assert!(
                    matches!(r, Ok(()) | Err(Code::NonCanonical)),
                    "offset {k}: {r:?}"
                );
            }
        }
        base = next;
    }
    base.done().expect("the whole input");
    (walked, skipped)
}

#[test]
fn every_prefix_and_mutation_of_the_jpeg_goldens_and_vectors() {
    let t = Instant::now();
    let mut inputs: Vec<(String, Vec<u8>)> = goldens(".jpg");
    inputs.push(("grey 320x208".into(), grey_jpeg(320, 208)));
    let mut total = (0, 0);
    for (name, data) in &inputs {
        let (w, s) = sweep(JpegChecker::new(), data, 1);
        total = (total.0 + w, total.1 + s);
        // jpegCanonicalize over the same mutations: never a panic, and its output always passes.
        for k in 0..data.len().min(4_096) {
            for v in values(data[k]) {
                let mut m = data.clone();
                m[k] = v;
                if let Ok(c) = jpeg::canonicalize(&m) {
                    jpeg::check(&c).unwrap_or_else(|e| {
                        panic!("{name} offset {k}: canonical output refused: {e}")
                    });
                }
            }
        }
    }
    eprintln!(
        "JPEG sweep: {} inputs, {} mutations walked, {} skipped, {:?}",
        inputs.len(),
        total.0,
        total.1,
        t.elapsed()
    );
}

#[test]
fn every_prefix_and_mutation_of_the_fmp4_goldens() {
    let t = Instant::now();
    let mut total = (0, 0);
    let mut bytes = 0;
    for (name, data) in goldens(".fmp4") {
        let stride = if name.contains("1080p60") && !full() {
            7
        } else {
            1
        };
        let (w, s) = sweep(Fmp4Checker::new(), &data, stride);
        total = (total.0 + w, total.1 + s);
        bytes += data.len();
    }
    eprintln!(
        "fMP4 sweep: {bytes} bytes, {} mutations walked, {} skipped, {:?}",
        total.0,
        total.1,
        t.elapsed()
    );
}

#[test]
fn every_prefix_and_byte_of_the_descriptors_and_manifests() {
    let text =
        std::fs::read_to_string(vectors_dir().join("media_descriptor.txt")).expect("vectors");
    let mut n = 0;
    for body in text.lines().filter_map(|l| l.strip_prefix("body = ")) {
        let body = hex::decode(body).expect("hex");
        for len in 0..=body.len() {
            let _ = Descriptor::decode(&body[..len]);
        }
        for k in 0..body.len() {
            for v in 0..=255u8 {
                let mut m = body.clone();
                m[k] = v;
                if let Err(e) = Descriptor::decode(&m) {
                    assert_eq!(e.code(), Code::NonCanonical);
                }
                n += 1;
            }
        }
    }
    // The manifest plaintexts of the vector objects: every offset of the fixed fields and the
    // preview, sampled offsets of the hash list and the tail.
    for spec in specs() {
        let o = honest(&spec);
        for k in (0..o.mp.len()).filter(|k| *k < 4_096 || k % 97 == 0) {
            for v in values(o.mp[k]) {
                let mut m = o.mp.clone();
                m[k] = v;
                if let Err(e) = Manifest::decode_plaintext(&m) {
                    assert_eq!(e.code(), Code::NonCanonical);
                }
                n += 1;
            }
        }
        for len in [0, 1, 37, 38, o.mp.len() - 1, o.mp.len() + 1] {
            let mut m = o.mp.clone();
            m.resize(len, 0);
            assert!(Manifest::decode_plaintext(&m).is_err());
        }
    }
    eprintln!("descriptor and manifest sweep: {n} inputs");
}

#[test]
fn every_prefix_and_mutation_of_the_sniffer_and_jpeg_vector_inputs() {
    for file in ["media_sniff.txt", "media_jpeg.txt"] {
        let text = std::fs::read_to_string(vectors_dir().join(file)).expect("vectors");
        for input in text.lines().filter_map(|l| l.strip_prefix("input = ")) {
            let data = recipe(input);
            let head = &data[..data.len().min(4_096)];
            for len in 0..=head.len() {
                let _ = sniff(&head[..len]);
                if file == "media_jpeg.txt" {
                    let _ = jpeg::check(&head[..len]);
                }
            }
            for k in 0..head.len() {
                for v in values(head[k]) {
                    let mut m = data.clone();
                    m[k] = v;
                    let _ = sniff(&m);
                    let _ = jpeg::check(&m);
                    let _ = jpeg::canonicalize(&m);
                }
            }
        }
    }
}
