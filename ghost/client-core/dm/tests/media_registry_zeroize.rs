//! The F3 zero-residue probe of the media registries' storage (the review round of §22.4,
//! finding F3): after `sealAbort`/`sealFinish`/`readerClose`-style removal and `ctxClose`-style
//! drop cycles, no readable copy of an entry's secrets remains in abandoned table memory.
//!
//! The probe shape mirrors the media crate's `tests/zeroize.rs`: a global allocator scans every
//! block freed on a thread while that thread is armed, this time for 32-byte key patterns (the
//! file key `K_f` and the derived payload key `K_p`) instead of a 16-byte content canary. The
//! registry types under test are `ghost_client_dm::jni_media::probe`'s: the boxed storage the
//! DM context's `media_sealers`/`media_readers` use today, and — as the "before" measurement —
//! the by-value shape the review found leaking (a hashbrown removal moves an entry out
//! bit-for-bit and marks the bucket empty without clearing it, so the vacated bytes keep the
//! entry's inline keys until the table is rehashed or freed; a growing table frees its old
//! allocation unerased — the residue class CRY-P9-02 fixed at the context level). Integration
//! tests live outside `src/` because the crate forbids `unsafe_code` and an allocator needs the
//! `unsafe impl`.
#![allow(clippy::disallowed_methods)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, RefCell};

use ghost_client_dm::jni_media::probe;
use ghost_client_media as media;

/// The canary file key `K_f`: the sealer entries hold it verbatim, the reader entries hold the
/// key derived from it, and both patterns are what the scan looks for.
const KF: [u8; 32] = *b"DMREG-F3PROBE-KF-CANARY-0000xyzz";
/// The one `object_id` every probe entry uses, so one derived `K_p` pattern covers both
/// registries.
const OID: [u8; 16] = *b"DMREGF3PROBE-OID";

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static HITS: Cell<usize> = const { Cell::new(0) };
    static PATTERNS: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

struct Scan;

// SAFETY: every call is forwarded to the system allocator; `dealloc` reads, then zeroes, the
// block it is handed (valid for `layout.size()` bytes until it is freed), then frees it — the
// media crate's `tests/zeroize.rs` scanner, generalised from one fixed canary to key patterns.
unsafe impl GlobalAlloc for Scan {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let armed = ARMED.try_with(Cell::get).unwrap_or(false);
        // `try_borrow`, never `borrow`: a drop that runs while `PATTERNS` is borrowed (the probe
        // replacing or clearing its patterns frees their buffers, which re-enters this
        // `dealloc`) must skip the scan, not panic inside the allocator.
        let shortest = PATTERNS
            .try_with(|p| {
                p.try_borrow()
                    .map(|b| b.iter().map(Vec::len).min().unwrap_or(0))
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        if armed && layout.size() >= shortest && shortest > 0 {
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            let hit = PATTERNS.try_with(|p| {
                p.try_borrow().map(|pats| {
                    pats.iter()
                        .filter(|pat| !pat.is_empty())
                        .any(|pat| block.windows(pat.len()).any(|w| w == pat.as_slice()))
                })
            });
            if matches!(hit, Ok(Ok(true))) {
                let _ = HITS.try_with(|h| h.set(h.get() + 1));
            }
        }
        // Every freed block is wiped after the scan, armed or not: a block the probe itself
        // freed with a pattern would otherwise come back as uninitialised capacity and be
        // reported when something else frees it (stale bytes, not the registries').
        unsafe {
            std::ptr::write_bytes(ptr, 0, layout.size());
            System.dealloc(ptr, layout)
        }
    }
}

#[global_allocator]
static GLOBAL: Scan = Scan;

/// Runs `f` armed against `patterns` and returns how many freed blocks held one of them.
fn scanned(patterns: &[Vec<u8>], f: impl FnOnce()) -> usize {
    HITS.with(|h| h.set(0));
    // Replace the patterns with the borrow released before `f` runs; `clear`/`extend` drop the
    // old buffers inside the borrow, and the nested deallocs skip the scan (`try_borrow`).
    PATTERNS.with(|p| {
        let mut b = p.borrow_mut();
        b.clear();
        b.extend(patterns.iter().cloned());
    });
    ARMED.with(|a| a.set(true));
    f();
    ARMED.with(|a| a.set(false));
    HITS.with(Cell::get)
}

/// `K_f` and the derived `K_p` of the probe's one `(K_f, object_id)` pair: the two 32-byte
/// patterns an entry carries inline (the sealer both, the reader the payload key).
fn patterns() -> Vec<Vec<u8>> {
    let derived = media::keys::derive(
        &media::FileKey::from_bytes(KF),
        &media::ObjectId::from_bytes(OID),
    );
    vec![KF.to_vec(), derived.payload.as_bytes().to_vec()]
}

// ---------------------------------------------------------------------------------------------
// A decodable canonical baseline grey JPEG, mirrored from the media crate's test support
// (`tests/support/mod.rs`): one component, the T.81 Annex K luminance tables, every block the
// 6-bit pattern `001010` (DC difference 0, immediate end-of-block), padded with ones. The
// sealer's walker accepts it; the probe needs one small image object per reader entry.

const K1_LUMA_DQT: [u8; 64] = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113,
    92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];
const DC_LUMA_BITS: [u8; 16] = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0];
const DC_LUMA_VALS: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
const AC_LUMA_BITS: [u8; 16] = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d];
const AC_LUMA_VALS: [u8; 162] = [
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
    0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0,
    0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
    0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
    0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa,
];

fn segment(out: &mut Vec<u8>, marker: u8, payload: &[u8]) {
    out.extend_from_slice(&[0xFF, marker]);
    out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(payload);
}

fn grey_header(w: u16, h: u16) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8];
    let mut dqt = vec![0x00];
    dqt.extend_from_slice(&K1_LUMA_DQT);
    segment(&mut v, 0xDB, &dqt);
    let mut sof = vec![8];
    sof.extend_from_slice(&h.to_be_bytes());
    sof.extend_from_slice(&w.to_be_bytes());
    sof.extend_from_slice(&[1, 1, 0x11, 0]);
    segment(&mut v, 0xC0, &sof);
    let mut dht = vec![0x00];
    dht.extend_from_slice(&DC_LUMA_BITS);
    dht.extend_from_slice(&DC_LUMA_VALS);
    dht.push(0x10);
    dht.extend_from_slice(&AC_LUMA_BITS);
    dht.extend_from_slice(&AC_LUMA_VALS);
    segment(&mut v, 0xC4, &dht);
    segment(&mut v, 0xDA, &[1, 1, 0x00, 0, 63, 0]);
    v
}

/// The entropy-coded data of `blocks` grey blocks (`001010` each), padded with one bits.
fn grey_blocks(blocks: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut n) = (0u32, 0u32);
    for _ in 0..blocks {
        acc = (acc << 6) | 0b001010;
        n += 6;
        while n >= 8 {
            out.push((acc >> (n - 8)) as u8);
            n -= 8;
        }
    }
    if n > 0 {
        out.push(((acc << (8 - n)) as u8) | ((1u32 << (8 - n)) - 1) as u8);
    }
    out
}

/// A decodable grey canonical JPEG of `w × h` (multiples of 8).
fn grey_jpeg(w: u16, h: u16) -> Vec<u8> {
    let blocks = (w as usize / 8) * (h as usize / 8);
    let mut v = grey_header(w, h);
    v.extend(grey_blocks(blocks));
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

// ---------------------------------------------------------------------------------------------

/// The seal the reader entries open on: one image object under the probe's `(K_f, object_id)`.
struct Object {
    blob: Vec<u8>,
    hash: [u8; 32],
}

fn seal_object() -> Object {
    let mut sealer = media::Sealer::begin(
        media::FileKey::from_bytes(KF),
        media::ObjectId::from_bytes(OID),
        media::MediaKind::Image,
        false,
        media::SizeClass::SMALLEST,
    );
    sealer.append(&grey_jpeg(512, 512)).expect("append");
    let sealed = sealer.finish(&grey_jpeg(320, 176)).expect("finish");
    Object {
        blob: sealed.manifest_blob.clone(),
        hash: sealed.manifest_hash,
    }
}

fn open_reader(object: &Object) -> media::Reader {
    let expected = media::Expected {
        object_id: media::ObjectId::from_bytes(OID),
        kind: media::MediaKind::Image,
        view_once: false,
        class: media::SizeClass::SMALLEST,
        manifest_hash: object.hash,
    };
    media::Reader::open(&media::FileKey::from_bytes(KF), &expected, &object.blob).expect("open")
}

/// One sealer registry's worth of insert/remove/rehash churn: live entries are a sliding
/// window of 16 while ids climb to 300, so the table grows (and frees its old allocations)
/// repeatedly; removals interleave, the way `sealAbort`/`sealFinish`/`readerClose` do.
fn seal_churn(sealers: &mut probe::SealerMap) {
    for i in 0..300i64 {
        sealers.insert(i, Box::new(probe::sealer_entry(KF, OID, [0x77; 16])));
        if i >= 16 {
            sealers.remove(&(i - 16));
        }
    }
}

fn reader_churn(readers: &mut probe::ReaderMap, object: &Object) {
    for i in 0..300i64 {
        readers.insert(i, Box::new(probe::reader_entry(open_reader(object), true)));
        if i >= 16 {
            readers.remove(&(i - 16));
        }
    }
}

/// The production storage: boxed entries. A removal moves the pointer out of the table and
/// drops the box, which zeroises `K_f`/`K_p` in place before the allocation is freed; the
/// abandoned table memory holds pointers only.
#[test]
fn boxed_registry_storage_leaves_no_key_residue() {
    let patterns = patterns();
    let object = seal_object();
    let hits = scanned(&patterns, || {
        let mut sealers: probe::SealerMap = std::collections::HashMap::new();
        seal_churn(&mut sealers);
        let mut readers: probe::ReaderMap = std::collections::HashMap::new();
        reader_churn(&mut readers, &object);
        // ctxClose: the maps drop with the context.
        drop((sealers, readers));
        drop(object);
    });
    assert_eq!(
        hits, 0,
        "boxed registry storage freed {hits} block(s) holding K_f or K_p"
    );
}

/// The pre-fix storage shape (by-value entries), measured not asserted — the count is
/// allocator-dependent, and the assertion lives on the boxed shape above. This is the probe
/// the review described: the same insert/remove/rehash cycles, the same scan, over the type
/// the registries used to have. Before the fix it prints a positive count (each freed table
/// block still holding a removed entry's stale key bytes); after, this same test still runs
/// against the preserved by-value aliases to document the residue class.
#[test]
fn by_value_entries_leave_the_residue_the_review_found() {
    let patterns = patterns();
    let object = seal_object();
    let hits = scanned(&patterns, || {
        let mut sealers: probe::ByValueSealerMap = std::collections::HashMap::new();
        for i in 0..300i64 {
            sealers.insert(i, probe::sealer_entry(KF, OID, [0x77; 16]));
            if i >= 16 {
                sealers.remove(&(i - 16));
            }
        }
        let mut readers: probe::ByValueReaderMap = std::collections::HashMap::new();
        for i in 0..300i64 {
            readers.insert(i, probe::reader_entry(open_reader(&object), true));
            if i >= 16 {
                readers.remove(&(i - 16));
            }
        }
        drop((sealers, readers));
        drop(object);
    });
    eprintln!("by-value registry storage freed {hits} block(s) holding K_f or K_p");
}
