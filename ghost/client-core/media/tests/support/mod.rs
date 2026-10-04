//! Shared test support: the goldens, a decodable canonical JPEG builder, a canonical fMP4 builder
//! that re-fragments a golden into a stream of any length, and a seeded generator.
#![allow(dead_code, clippy::disallowed_methods)]

use std::path::PathBuf;

use ghost_client_media::fmp4::{build_mfra, MoofEntry};

pub mod boxes;
pub mod replay;

/// `ghost/protocol/test-vectors`.
pub fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../protocol/test-vectors")
}

/// The committed goldens of Media3 1.11.1 (§8.3, G-M8).
pub fn goldens_dir() -> PathBuf {
    vectors_dir().join("media-goldens/media3-1.11.1")
}

/// Every golden: `(relative path, bytes)`, sorted.
pub fn goldens(ext: &str) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for level in ["api29-emulator", "api35-emulator"] {
        let dir = goldens_dir().join(level);
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .expect("goldens directory")
            .map(|e| e.expect("entry").file_name().into_string().expect("utf-8"))
            .filter(|n| n.ends_with(ext))
            .collect();
        names.sort();
        for n in names {
            let bytes = std::fs::read(dir.join(&n)).expect("golden");
            out.push((format!("{level}/{n}"), bytes));
        }
    }
    assert!(!out.is_empty(), "no {ext} golden found");
    out
}

/// One golden by its path relative to `media3-1.11.1/`.
pub fn golden(rel: &str) -> Vec<u8> {
    std::fs::read(goldens_dir().join(rel)).expect("golden")
}

/// A deterministic xorshift64* stream: inputs for property runs, never a key.
pub struct Seeded(u64);

impl Seeded {
    pub fn new(seed: u64) -> Self {
        Seeded(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
    pub fn key32(&mut self) -> [u8; 32] {
        let mut k = [0u8; 32];
        for b in k.iter_mut() {
            *b = self.next_u64() as u8;
        }
        k
    }
    pub fn id16(&mut self) -> [u8; 16] {
        let mut k = [0u8; 16];
        for b in k.iter_mut() {
            *b = self.next_u64() as u8;
        }
        k
    }
}

/// SHA-256-counter bytes: `SHA-256(seed || u32_be(0)) || SHA-256(seed || u32_be(1)) || …`.
pub fn sha256ctr(seed: &str, len: usize) -> Vec<u8> {
    use sha2_shim::digest;
    let mut out = Vec::with_capacity(len + 32);
    let mut i = 0u32;
    while out.len() < len {
        let mut input = seed.as_bytes().to_vec();
        input.extend_from_slice(&i.to_be_bytes());
        out.extend_from_slice(&digest(&input));
        i += 1;
    }
    out.truncate(len);
    out
}

/// SHA-256 through the crate's own helper (the tests do not link sha2 directly).
pub mod sha2_shim {
    pub fn digest(data: &[u8]) -> [u8; 32] {
        ghost_client_media::keys::sha256(data)
    }
}

// ---------------------------------------------------------------------------------------------
// A decodable canonical baseline JPEG: a uniform mid-grey picture, one component, the standard
// luminance tables of ITU-T T.81 Annex K. Every block codes DC difference 0 (category 0, code
// `00`) and an immediate end-of-block (`1010`), so the entropy-coded data is the 6-bit pattern
// `001010` once per 8 × 8 block, padded with ones (`grey_jpeg`). A canonical file of an exact
// length is built differently (`jpeg_of_len`): the same header, opaque filler in the scan.

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

/// The header of a grey `w × h` baseline JPEG up to and including its SOS, with restart interval
/// `restart` (0: none).
fn grey_header(w: u16, h: u16, restart: u16) -> Vec<u8> {
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
    if restart > 0 {
        segment(&mut v, 0xDD, &restart.to_be_bytes());
    }
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
pub fn grey_jpeg(w: u16, h: u16) -> Vec<u8> {
    let blocks = (w as usize / 8) * (h as usize / 8);
    let mut v = grey_header(w, h, 0);
    v.extend(grey_blocks(blocks));
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

/// A canonical JPEG of `w × h` and exactly `len` bytes: the grey header with a restart interval of
/// one MCU, then one `001010` block per interval separated by RST markers, and opaque filler bytes
/// (never 0xFF) inside the last interval to reach the length. The walker does not decode, so the
/// filler is canonical; it is not a picture a decoder would show. `len` must be at least the
/// header plus a few bytes.
pub fn jpeg_of_len(w: u16, h: u16, len: usize) -> Vec<u8> {
    let mut v = grey_header(w, h, 1);
    let mut rst = 0u8;
    // Two restart intervals, then filler, then EOI.
    v.extend(grey_blocks(1));
    v.extend_from_slice(&[0xFF, 0xD0 + rst]);
    rst = (rst + 1) % 8;
    let _ = rst;
    assert!(
        len >= v.len() + 3,
        "a {len}-byte JPEG is too short for its header"
    );
    let filler = len - v.len() - 2;
    v.extend((0..filler).map(|i| (i % 251) as u8 + 1));
    v.extend_from_slice(&[0xFF, 0xD9]);
    assert_eq!(v.len(), len);
    v
}

// ---------------------------------------------------------------------------------------------
// fMP4 surgery on the goldens.

/// A top-level box: `(offset, size, type)`.
pub fn top_boxes(data: &[u8]) -> Vec<(usize, usize, [u8; 4])> {
    let mut out = Vec::new();
    let mut o = 0;
    while o + 8 <= data.len() {
        let size = u32::from_be_bytes(data[o..o + 4].try_into().unwrap()) as usize;
        let typ: [u8; 4] = data[o + 4..o + 8].try_into().unwrap();
        out.push((o, size, typ));
        if size < 8 {
            break;
        }
        o += size;
    }
    out
}

/// The golden without its `mfra`: the muxer's output as the sealer sees it.
pub fn without_mfra(data: &[u8]) -> Vec<u8> {
    let boxes = top_boxes(data);
    let last = boxes.last().expect("boxes");
    assert_eq!(&last.2, b"mfra");
    data[..last.0].to_vec()
}

/// Finds the offset of the first `typ` box inside `data[from..to]`, descending into containers.
pub fn find_box(data: &[u8], from: usize, to: usize, typ: &[u8; 4]) -> Option<usize> {
    const CONTAINERS: [&[u8; 4]; 9] = [
        b"moov", b"trak", b"mdia", b"minf", b"dinf", b"stbl", b"mvex", b"moof", b"traf",
    ];
    let mut o = from;
    while o + 8 <= to {
        let size = u32::from_be_bytes(data[o..o + 4].try_into().unwrap()) as usize;
        let t: [u8; 4] = data[o + 4..o + 8].try_into().unwrap();
        if &t == typ {
            return Some(o);
        }
        if size < 8 {
            return None;
        }
        if CONTAINERS.contains(&&t) {
            if let Some(found) = find_box(data, o + 8, o + size, typ) {
                return Some(found);
            }
        }
        if &t == b"stsd" {
            let entry = o + 16;
            let esize = u32::from_be_bytes(data[entry..entry + 4].try_into().unwrap()) as usize;
            let et: [u8; 4] = data[entry + 4..entry + 8].try_into().unwrap();
            let fixed = if &et == b"avc1" { 78 } else { 28 };
            if &et == typ {
                return Some(entry);
            }
            if let Some(found) = find_box(data, entry + 8 + fixed, entry + esize, typ) {
                return Some(found);
            }
        }
        o += size;
    }
    None
}

/// A fragment of a golden: its `moof` and `mdat` bytes, and per track its sample durations.
#[derive(Clone)]
pub struct Fragment {
    pub moof: Vec<u8>,
    pub mdat: Vec<u8>,
}

/// The `moov` (with `ftyp`) and the fragments of a golden.
pub fn split(data: &[u8]) -> (Vec<u8>, Vec<Fragment>) {
    let boxes = top_boxes(data);
    let head_end = boxes[2].0;
    let mut frags = Vec::new();
    let mut i = 2;
    while i + 1 < boxes.len() && &boxes[i].2 == b"moof" {
        let (mo, ms, _) = boxes[i];
        let (do_, ds, _) = boxes[i + 1];
        frags.push(Fragment {
            moof: data[mo..mo + ms].to_vec(),
            mdat: data[do_..do_ + ds].to_vec(),
        });
        i += 2;
    }
    (data[..head_end].to_vec(), frags)
}

fn put_u32(v: &mut [u8], at: usize, x: u32) {
    v[at..at + 4].copy_from_slice(&x.to_be_bytes());
}
fn put_u64(v: &mut [u8], at: usize, x: u64) {
    v[at..at + 8].copy_from_slice(&x.to_be_bytes());
}
pub fn get_u32(v: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(v[at..at + 4].try_into().unwrap())
}
fn get_u64(v: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(v[at..at + 8].try_into().unwrap())
}

/// Per-traf `(tfhd offset, tfdt offset, trun offset)` inside a `moof`'s bytes.
pub fn trafs(moof: &[u8]) -> Vec<(usize, usize, usize)> {
    let mut out = Vec::new();
    let mut o = 8;
    while o + 8 <= moof.len() {
        let size = get_u32(moof, o) as usize;
        if &moof[o + 4..o + 8] == b"traf" {
            let tfhd = o + 8;
            let tfdt = tfhd + get_u32(moof, tfhd) as usize;
            let trun = tfdt + get_u32(moof, tfdt) as usize;
            out.push((tfhd, tfdt, trun));
        }
        o += size;
    }
    out
}

/// Re-stamps a sequence of fragments taken from goldens into one canonical stream after `head`:
/// sequence numbers, `base_data_offset`s and `tfdt`s follow the new positions, and the `mfra` is
/// appended when `with_mfra`. Returns the stream.
pub fn restamp(head: &[u8], frags: &[Fragment], with_mfra: bool) -> Vec<u8> {
    let mut out = head.to_vec();
    let mut times = [0u64; 2];
    let mut moofs = Vec::new();
    let video_track = video_track_of(head);
    for (n, f) in frags.iter().enumerate() {
        let offset = out.len() as u64;
        let mut moof = f.moof.clone();
        put_u32(&mut moof, 8 + 12, n as u32 + 1);
        let mut video_time = 0;
        for (t, (tfhd, tfdt, trun)) in trafs(&moof).into_iter().enumerate() {
            put_u64(&mut moof, tfhd + 16, offset);
            put_u64(&mut moof, tfdt + 12, times[t]);
            if t as u32 + 1 == video_track {
                video_time = times[t];
            }
            let count = get_u32(&moof, trun + 12) as usize;
            let mut sum = 0u64;
            for s in 0..count {
                sum += get_u32(&moof, trun + 20 + 12 * s) as u64;
            }
            times[t] += sum;
        }
        moofs.push(MoofEntry { offset, video_time });
        out.extend_from_slice(&moof);
        out.extend_from_slice(&f.mdat);
    }
    if with_mfra {
        out.extend(build_mfra(video_track, &moofs));
    }
    out
}

/// The video track ID of a stream's `moov` (1 or 2).
pub fn video_track_of(head: &[u8]) -> u32 {
    let hdlr = find_box(head, 0, head.len(), b"hdlr").expect("hdlr");
    // The first trak's handler: video when it is `vide`.
    if &head[hdlr + 16..hdlr + 20] == b"vide" {
        1
    } else {
        2
    }
}

/// A canonical stream of exactly `len` content bytes (with its `mfra`), `len` at least about
/// 110 kB: `k = ⌈len / 12 MiB⌉` fragments taken in turn from the API 35 `quad_land` golden, the
/// last video sample of each grown (its NAL unit's opaque payload) to share the length, so every
/// fragment stays below 16 MiB and the duration a few seconds. Not a picture a decoder would show
/// where the payload grew; every structural rule of the profile holds.
pub fn fmp4_of_len(len: usize) -> Vec<u8> {
    let golden = golden("api35-emulator/quad_land.fmp4");
    let (head, frags) = split(&golden);
    let per = 12 * 1024 * 1024;
    let k = len.div_ceil(per).max(1);
    let mut seq: Vec<Fragment> = (0..k).map(|i| frags[i % frags.len()].clone()).collect();
    let mfra_len = 8 + 24 + 19 * k + 16;
    let base = head.len()
        + seq
            .iter()
            .map(|f| f.moof.len() + f.mdat.len())
            .sum::<usize>()
        + mfra_len;
    assert!(len >= base, "fmp4_of_len({len}): at least {base} bytes");
    let extra = len - base;
    let each = extra / k;
    for (i, f) in seq.iter_mut().enumerate() {
        let d = if i + 1 == k {
            extra - each * (k - 1)
        } else {
            each
        };
        resize_last_video_sample(f, d as i64);
    }
    let out = restamp(&head, &seq, true);
    assert_eq!(out.len(), len, "fmp4_of_len({len})");
    out
}

/// Grows (or shrinks) the last video sample of a fragment by `delta` bytes inside its NAL unit's
/// opaque payload, with every size, length and offset that follows it.
pub fn resize_last_video_sample(f: &mut Fragment, delta: i64) {
    let video_track = 2; // the quad goldens: audio is track 1
    let tr = trafs(&f.moof);
    let (_, _, trun) = tr[video_track - 1];
    let count = get_u32(&f.moof, trun + 12) as usize;
    let row = trun + 20 + 12 * (count - 1);
    let size = get_u32(&f.moof, row + 4) as i64;
    let new_size = size + delta;
    assert!(new_size >= 16, "cannot shrink a sample below 16 bytes");
    put_u32(&mut f.moof, row + 4, new_size as u32);
    // The sample is the last bytes of the mdat; its one NAL unit's length prefix is its first four.
    let mdat_payload = f.mdat.len() - 8;
    let start = 8 + mdat_payload - size as usize;
    let nal_len = get_u32(&f.mdat, start) as i64;
    assert_eq!(nal_len + 4, size, "one NAL unit per sample");
    let mut sample = f.mdat[start..].to_vec();
    if delta >= 0 {
        sample.extend((0..delta).map(|i| (i % 200) as u8 + 0x20));
    } else {
        sample.truncate((size + delta) as usize);
    }
    put_u32(&mut sample, 0, (new_size - 4) as u32);
    f.mdat.truncate(start);
    f.mdat.extend(sample);
    let mdat_size = f.mdat.len() as u32;
    put_u32(&mut f.mdat, 0, mdat_size);
}

// ---------------------------------------------------------------------------------------------
// Builders shared by the fMP4 vectors and the RAM test.

/// The avcC body of `sps` and `pps`, with the High extension when `ext`.
pub fn avcc(sps: &[u8], pps: &[u8], ext: bool) -> Vec<u8> {
    let mut v = vec![1, sps[1], sps[2], sps[3], 0xFF, 0xE1];
    v.extend_from_slice(&(sps.len() as u16).to_be_bytes());
    v.extend_from_slice(sps);
    v.push(1);
    v.extend_from_slice(&(pps.len() as u16).to_be_bytes());
    v.extend_from_slice(pps);
    if ext {
        v.extend_from_slice(&[0xFD, 0xF8, 0xF8, 0x00]);
    }
    v
}

/// The path of the video track's `avcC` in a golden's box tree (the video track is the second).
pub fn avcc_path() -> Vec<&'static str> {
    vec![
        "moov", "trak#1", "mdia", "minf", "stbl", "stsd", "avc1", "avcC",
    ]
}

/// The SPS and PPS NAL units of a stream's `avcC`.
pub fn parameter_sets(head: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let off = find_box(head, 0, head.len(), b"avcC").expect("avcC");
    let body = &head[off + 8..off + get_u32(head, off) as usize];
    let sps_len = u16::from_be_bytes([body[6], body[7]]) as usize;
    let sps = body[8..8 + sps_len].to_vec();
    let at = 8 + sps_len + 1;
    let pps_len = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
    let pps = body[at + 2..at + 2 + pps_len].to_vec();
    (sps, pps)
}

/// An SEI NAL unit with one message of `payload_type` (payload under 255 bytes).
pub fn sei(payload_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x06, payload_type, payload.len() as u8];
    v.extend_from_slice(payload);
    v.push(0x80);
    v
}

/// The edit of a golden's `moov` (`head_edit`) and fragments (`frag_edit`), the fragments
/// restamped to the new `moov` size, with the `mfra`: a canonical stream when the edits are.
pub fn restamped(
    g: &[u8],
    head_edit: impl FnOnce(&mut Vec<boxes::Node>),
    frag_edit: impl Fn(usize, &mut Fragment),
) -> Vec<u8> {
    let (head, mut frags) = split(g);
    let mut nodes = boxes::parse(&head);
    head_edit(&mut nodes);
    let head = boxes::serialize(&nodes);
    for (i, fr) in frags.iter_mut().enumerate() {
        frag_edit(i, fr);
    }
    restamp(&head, &frags, true)
}

/// Inserts NAL units (with 4-byte lengths) at the start of the first video sample of a fragment
/// of a golden whose video track is the second (`trafs()[1]`).
pub fn prepend_to_first_video_sample(fr: &mut Fragment, nals: &[Vec<u8>]) {
    let mut bytes = Vec::new();
    for n in nals {
        bytes.extend_from_slice(&(n.len() as u32).to_be_bytes());
        bytes.extend_from_slice(n);
    }
    let tr = trafs(&fr.moof);
    let (_, _, vtrun) = tr[1];
    let data_offset = get_u32(&fr.moof, vtrun + 16) as usize;
    let first_size = get_u32(&fr.moof, vtrun + 20 + 4);
    let at_mdat = data_offset - fr.moof.len();
    fr.moof[vtrun + 24..vtrun + 28]
        .copy_from_slice(&(first_size + bytes.len() as u32).to_be_bytes());
    let mut mdat = fr.mdat[..at_mdat].to_vec();
    mdat.extend_from_slice(&bytes);
    mdat.extend_from_slice(&fr.mdat[at_mdat..]);
    let size = mdat.len() as u32;
    mdat[..4].copy_from_slice(&size.to_be_bytes());
    fr.mdat = mdat;
}
