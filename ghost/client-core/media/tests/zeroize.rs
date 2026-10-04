//! RAM hygiene of the crate's own buffers (design §10.5 "native buffers … are zeroised on release",
//! §15.2 item 8 "every … native buffer is zero when released"; the review of S1, finding 2): no
//! block the crate frees holds plaintext or key bytes.
//!
//! A global allocator scans every block freed on a thread while that thread is armed for a
//! 16-byte canary planted in the content (slice data, entropy-coded data, a quantisation table,
//! the PPS, an SEI payload, the preview) or in the descriptor's key slot. `realloc` is the
//! default one (`alloc`, copy, `dealloc`), so a buffer that grows in place hands its old block to
//! the scan with its bytes: that is how S1's first sealer left the last partial chunk of every
//! video in freed memory (`mem::take` emptied the held buffer, and the next append regrew it).
//! Arming is per thread, so the other tests of this binary running in parallel are not scanned.
//! Integration tests are outside `src/`: the `unsafe impl` an allocator needs is not the crate's
//! (`#![forbid(unsafe_code)]` and `media-crate-purity.sh` cover `src/`).
#![allow(clippy::disallowed_methods)]

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use ghost_client_media::consts::CHUNK_PT;
use ghost_client_media::jpeg;
use ghost_client_media::{
    Descriptor, Expected, FileKey, KeySlot, MediaKind, ObjectId, Reader, Sealer, SizeClass,
};
use support::boxes::at;
use support::*;

const CANARY: [u8; 16] = *b"PLAINTXT-CANARY!";

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static HITS: Cell<usize> = const { Cell::new(0) };
}

struct Scan;

// SAFETY: every call is forwarded to the system allocator; `dealloc` reads, then zeroes, the
// block it is handed (valid for `layout.size()` bytes until it is freed), then frees it.
unsafe impl GlobalAlloc for Scan {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let armed = ARMED.try_with(Cell::get).unwrap_or(false);
        if armed && layout.size() >= CANARY.len() {
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if block.windows(CANARY.len()).any(|w| w == CANARY) {
                let _ = HITS.try_with(|h| h.set(h.get() + 1));
            }
        }
        // Every freed block is wiped after the scan, armed or not: a block the test itself freed
        // with the canary would otherwise come back to the crate as uninitialised capacity and be
        // reported when the crate frees it (stale bytes, not the crate's).
        unsafe {
            std::ptr::write_bytes(ptr, 0, layout.size());
            System.dealloc(ptr, layout)
        }
    }
}

#[global_allocator]
static GLOBAL: Scan = Scan;

/// Runs `f` armed and returns how many freed blocks held the canary.
fn scanned<T>(f: impl FnOnce() -> T) -> (T, usize) {
    HITS.with(|h| h.set(0));
    ARMED.with(|a| a.set(true));
    let out = f();
    ARMED.with(|a| a.set(false));
    (out, HITS.with(Cell::get))
}

fn plant(buf: &mut [u8], at: usize) {
    buf[at..at + CANARY.len()].copy_from_slice(&CANARY);
}

/// Seals `input` in `pieces`, then reads the object back (validation pass and reads), each step
/// scanned; returns the hits of the appends, the finish and the reader.
fn seal_and_read(kind: MediaKind, input: &[u8], pieces: &[usize]) -> (usize, usize, usize) {
    let key = FileKey::from_bytes([0x37; 32]);
    let id = ObjectId::from_bytes([0x38; 16]);
    let mut sealer = Sealer::begin(key.clone(), id, kind, false, SizeClass::LARGEST);
    let mut chunks = Vec::new();
    let mut at = 0;
    let mut appended = 0;
    for &p in pieces {
        let (r, hits) = scanned(|| sealer.append(&input[at..at + p]));
        chunks.extend(r.expect("append"));
        appended += hits;
        at += p;
    }
    assert_eq!(at, input.len());
    let preview = {
        // The canary in the preview's quantisation table too: the manifest's copies and the
        // preview's walk.
        let mut p = grey_jpeg(320, 176);
        plant(&mut p, 2 + 4 + 1 + 8);
        p
    };
    let (sealed, finished) = scanned(|| sealer.finish(&preview));
    let sealed = sealed.expect("finish");
    chunks.extend(sealed.chunks.iter().cloned());
    let expected = Expected {
        object_id: id,
        kind,
        view_once: false,
        class: sealed.manifest.fields.class,
        manifest_hash: sealed.manifest_hash,
    };
    let mut out = vec![0u8; CHUNK_PT];
    let ((), read) = scanned(|| {
        let mut r = Reader::open(&key, &expected, &sealed.manifest_blob).expect("open");
        for c in &chunks {
            r.validate_chunk(c.index, &c.ciphertext).expect("validate");
        }
        r.validate_finish().expect("finish");
        for c in &chunks {
            r.read_chunk(c.index, &c.ciphertext, &mut out)
                .expect("read");
        }
    });
    drop(out);
    (appended, finished, read)
}

fn pieces_of(len: usize, size: usize) -> Vec<usize> {
    let mut v = vec![size; len / size];
    if !len.is_multiple_of(size) {
        v.push(len % size);
    }
    v
}

/// A canonical video of about `len` bytes with the canary in its PPS, in an SEI payload of the
/// first fragment and, when `in_slice`, in the slice data of the last video sample.
fn video_with_canaries(len: usize, in_slice: bool) -> Vec<u8> {
    let base = fmp4_of_len(len);
    let (head, _) = split(&base);
    let (sps, mut pps) = parameter_sets(&head);
    pps.extend_from_slice(&CANARY);
    let stream = restamped(
        &base,
        |n| *at(n, &avcc_path()).body_mut() = avcc(&sps, &pps, false),
        |i, fr| {
            if i == 0 {
                prepend_to_first_video_sample(
                    fr,
                    &[sei(6, &[&[0x84, 0x00][..], &CANARY].concat())],
                );
            }
        },
    );
    let mut stream = stream;
    if in_slice {
        // The last bytes before the mfra: the last video sample's slice data.
        let l = without_mfra(&stream).len();
        plant(&mut stream, l - 64);
    }
    ghost_client_media::fmp4::check(&stream).expect("the planted stream is canonical");
    without_mfra(&stream)
}

#[test]
fn the_sealer_and_the_reader_free_no_plaintext() {
    // (1) A video fed as §6.2's SealingChannel feeds it: whole chunks, then the remainder; the
    // canary in the last partial chunk (the case the review measured: 213 549 bytes left).
    let input = video_with_canaries(1_000_000, true);
    let pieces = {
        let mut v = vec![CHUNK_PT; input.len() / CHUNK_PT];
        v.push(input.len() % CHUNK_PT);
        v
    };
    assert_eq!(
        seal_and_read(MediaKind::Video, &input, &pieces),
        (0, 0, 0),
        "video in SealingChannel pieces: freed blocks with the canary (appends, finish, reader)"
    );
    // (2) The same in 100 003-byte pieces (the vector replay's), and in pieces of 997 bytes,
    // which split the moov, the moofs and the SEI across appends (the walker's buffers grow).
    for size in [100_003, 997] {
        assert_eq!(
            seal_and_read(MediaKind::Video, &input, &pieces_of(input.len(), size)),
            (0, 0, 0),
            "video in {size}-byte pieces"
        );
    }
    // (3) An image in 4 096-byte and 7-byte pieces: the canary in the entropy-coded data (chunk
    // 1) and in the quantisation table (the walker's segment buffer).
    let mut img = jpeg_of_len(1024, 768, 900_000);
    plant(&mut img, CHUNK_PT + 1_000);
    plant(&mut img, 2 + 4 + 1 + 8);
    jpeg::check(&img).expect("the planted image is canonical");
    for size in [4096, 7] {
        assert_eq!(
            seal_and_read(MediaKind::Image, &img, &pieces_of(img.len(), size)),
            (0, 0, 0),
            "image in {size}-byte pieces"
        );
    }
}

#[test]
fn canonicalize_frees_no_picture_on_success_or_refusal() {
    let mut img = jpeg_of_len(1024, 768, 300_000);
    plant(&mut img, 200_000);
    let mut with_app1 = img.clone();
    with_app1.splice(2..2, [0xFF, 0xE1, 0x00, 0x06, b'E', b'x', b'i', b'f']);
    // Refused at its very end (a byte after EOI, as the Ultra HDR trailer is): the output written
    // so far is wiped.
    let mut trailer = with_app1.clone();
    trailer.push(0x00);
    let (r, hits) = scanned(|| jpeg::canonicalize(&trailer).map(|_| ()));
    assert!(r.is_err());
    assert_eq!(
        hits, 0,
        "a refused canonicalisation freed the picture unwiped"
    );
    // Accepted, then dropped the way S2 drops it after copying the bytes out.
    let ok = jpeg::canonicalize(&with_app1).expect("canonical");
    assert_eq!(*ok, img);
    let ((), hits) = scanned(|| drop(ok));
    assert_eq!(hits, 0, "the canonical output was freed unwiped");
}

#[test]
fn an_encoded_descriptor_frees_no_key() {
    let mut slot = [0u8; 32];
    slot[..16].copy_from_slice(&CANARY);
    slot[16..].copy_from_slice(&CANARY);
    let d = Descriptor {
        kind: MediaKind::Video,
        view_once: false,
        class: SizeClass::SMALLEST,
        object_id: ObjectId::from_bytes([9; 16]),
        key_slot: KeySlot::from_bytes(slot),
        manifest_hash: [7; 32],
        caption: String::new(),
    };
    let ((), hits) = scanned(|| {
        let body = d.encode().expect("encode");
        assert_eq!(&body[20..36], &CANARY);
    });
    assert_eq!(
        hits, 0,
        "the encoded body (K_f in its slot inside S2's encrypt) was freed unwiped"
    );
}
