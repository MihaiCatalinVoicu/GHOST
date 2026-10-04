//! `protocol/test-vectors/media_fmp4.txt` (design §8.3, §15.2 item 6; S0-2, S0-3, S0-13, S0-20,
//! S0-22): the walk of every committed golden, and the fMP4 negative corpus as data, each case a
//! byte recipe over a golden with the code the walker must give; plus the positive structural
//! cases the profile allows and no golden shows (a High-profile SPS with scaling lists, the BT.709
//! label, the video track first, allowed SEI, AUD and in-band parameter sets).
//!
//! `GHOST_WRITE_VECTORS=1 cargo test -p ghost-client-media --test fmp4_vectors` rewrites the file.
#![allow(clippy::disallowed_methods)]

mod support;

use std::fmt::Write as _;

use ghost_client_media::fmp4;
use ghost_client_media::keys::sha256;
use ghost_client_media::Code;
use support::boxes::{self, at, leaf, Node};
use support::replay::recipe;
use support::*;

const BASE: &str = "api35-emulator/quad_land.fmp4";
const BASE29: &str = "api29-emulator/quad_land.fmp4";

fn writing() -> bool {
    std::env::var("GHOST_WRITE_VECTORS").is_ok_and(|v| v == "1")
}

/// `golden[..p] + hex:middle + golden[s..]` for a mutation `m` of golden `g`.
fn diff_recipe(path: &str, g: &[u8], m: &[u8]) -> String {
    let p = g.iter().zip(m.iter()).take_while(|(a, b)| a == b).count();
    let max_s = g.len().min(m.len()) - p;
    let s = g
        .iter()
        .rev()
        .zip(m.iter().rev())
        .take(max_s)
        .take_while(|(a, b)| a == b)
        .count();
    let mut parts = Vec::new();
    if p > 0 {
        parts.push(format!("golden:{path}[0..{p}]"));
    }
    let middle = &m[p..m.len() - s];
    if !middle.is_empty() || (p == 0 && s == 0) {
        parts.push(format!("hex:{}", hex::encode(middle)));
    }
    if s > 0 {
        parts.push(format!("golden:{path}[{}..]", g.len() - s));
    }
    let r = parts.join(" + ");
    assert_eq!(recipe(&r), m, "the recipe rebuilds the input");
    r
}

fn head_len(g: &[u8]) -> usize {
    top_boxes(g)[2].0
}

/// The golden with its `ftyp` + `moov` edited (later bytes unchanged: a refusal in the `moov` comes
/// before any of them is read).
fn with_head(g: &[u8], f: impl FnOnce(&mut Vec<Node>)) -> Vec<u8> {
    let hl = head_len(g);
    let mut nodes = boxes::parse(&g[..hl]);
    f(&mut nodes);
    let mut m = boxes::serialize(&nodes);
    m.extend_from_slice(&g[hl..]);
    m
}

fn patch(g: &[u8], off: usize, bytes: &[u8]) -> Vec<u8> {
    let mut m = g.to_vec();
    m[off..off + bytes.len()].copy_from_slice(bytes);
    m
}

fn insert(g: &[u8], off: usize, bytes: &[u8]) -> Vec<u8> {
    let mut m = g[..off].to_vec();
    m.extend_from_slice(bytes);
    m.extend_from_slice(&g[off..]);
    m
}

const VIDEO: [&str; 2] = ["moov", "trak#1"];
const AUDIO: [&str; 2] = ["moov", "trak#0"];

fn path<'a>(base: &[&'a str], rest: &[&'a str]) -> Vec<&'a str> {
    base.iter().chain(rest.iter()).copied().collect()
}

fn set_body(nodes: &mut [Node], p: &[&str], off: usize, bytes: &[u8]) {
    let b = at(nodes, p).body_mut();
    b[off..off + bytes.len()].copy_from_slice(bytes);
}

/// The avcC body of `sps` and `pps`, with the High extension when `ext`.
fn avcc(sps: &[u8], pps: &[u8], ext: bool) -> Vec<u8> {
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

const PPS: [u8; 6] = [0x68, 0xce, 0x01, 0xa8, 0x35, 0xc8];
const AVCC: [&str; 9] = [
    "moov", "trak#1", "mdia", "minf", "stbl", "stsd", "avc1", "avcC", "",
];

fn avcc_path() -> Vec<&'static str> {
    AVCC[..8].to_vec()
}

// ---------------------------------------------------------------------------------------------
// SPS fixtures.

#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    bits: usize,
}

impl BitWriter {
    fn u(&mut self, n: u32, v: u64) -> &mut Self {
        for i in (0..n).rev() {
            if self.bits.is_multiple_of(8) {
                self.bytes.push(0);
            }
            let bit = ((v >> i) & 1) as u8;
            *self.bytes.last_mut().unwrap() |= bit << (7 - self.bits % 8);
            self.bits += 1;
        }
        self
    }
    fn ue(&mut self, v: u64) -> &mut Self {
        let x = v + 1;
        let len = 64 - x.leading_zeros();
        self.u(len - 1, 0).u(len, x)
    }
    fn se(&mut self, v: i64) -> &mut Self {
        let k = if v > 0 { 2 * v - 1 } else { -2 * v };
        self.ue(k as u64)
    }
    fn nal(&mut self, header: u8) -> Vec<u8> {
        self.u(1, 1);
        while !self.bits.is_multiple_of(8) {
            self.u(1, 0);
        }
        let mut out = vec![header];
        let mut zeros = 0;
        for &b in &self.bytes {
            if zeros >= 2 && b <= 3 {
                out.push(3);
                zeros = 0;
            }
            out.push(b);
            zeros = if b == 0 { zeros + 1 } else { 0 };
        }
        out
    }
}

/// An SPS of the given profile with every option the walker reads, for fixtures.
#[allow(clippy::too_many_arguments)]
fn sps(
    profile: u64,
    level: u64,
    chroma: u64,
    depth: u64,
    scaling: bool,
    frame_mbs_only: u64,
    mbs: (u64, u64),
    full_range: u64,
    colour: Option<(u64, u64, u64)>,
) -> Vec<u8> {
    let mut w = BitWriter::default();
    w.u(8, profile)
        .u(8, if profile == 66 { 0xc0 } else { 0 })
        .u(8, level)
        .ue(0);
    if profile == 100 {
        w.ue(chroma)
            .ue(depth)
            .ue(depth)
            .u(1, 0)
            .u(1, u64::from(scaling));
        if scaling {
            for i in 0..8 {
                w.u(1, 1);
                for j in 0..(if i < 6 { 16 } else { 64 }) {
                    w.se(if j % 2 == 0 { 1 } else { -1 });
                }
            }
        }
    }
    w.ue(0)
        .ue(2)
        .ue(1)
        .u(1, 0)
        .ue(mbs.0 - 1)
        .ue(mbs.1 - 1)
        .u(1, frame_mbs_only);
    if frame_mbs_only == 0 {
        w.u(1, 0);
    }
    w.u(1, 1).u(1, 0); // direct_8x8, no cropping
    w.u(1, 1); // VUI
    w.u(1, 0).u(1, 0); // no aspect, no overscan
    match colour {
        Some((p, t, m)) => {
            w.u(1, 1)
                .u(3, 5)
                .u(1, full_range)
                .u(1, 1)
                .u(8, p)
                .u(8, t)
                .u(8, m);
        }
        None => {
            w.u(1, 1).u(3, 5).u(1, full_range).u(1, 0);
        }
    }
    w.u(1, 0).u(1, 0).u(1, 0).u(1, 0).u(1, 0).u(1, 0); // chroma loc, timing, hrd x2, pic_struct, restriction
    w.nal(0x67)
}

fn baseline_sps() -> Vec<u8> {
    sps(66, 31, 1, 0, false, 1, (80, 45), 0, Some((5, 1, 6)))
}

fn high_sps() -> Vec<u8> {
    sps(100, 31, 1, 0, true, 1, (80, 45), 0, Some((5, 1, 6)))
}

fn with_sps(g: &[u8], sps_nal: &[u8], ext: bool) -> Vec<u8> {
    with_head(g, |n| {
        *at(n, &avcc_path()).body_mut() = avcc(sps_nal, &PPS, ext)
    })
}

/// The same edit with the fragments restamped to the new `moov` size (a positive case).
fn restamped(
    g: &[u8],
    f: impl FnOnce(&mut Vec<Node>),
    frag_edit: impl Fn(usize, &mut Fragment),
) -> Vec<u8> {
    let (head, mut frags) = split(g);
    let mut nodes = boxes::parse(&head);
    f(&mut nodes);
    let head = boxes::serialize(&nodes);
    for (i, fr) in frags.iter_mut().enumerate() {
        frag_edit(i, fr);
    }
    restamp(&head, &frags, true)
}

/// Inserts NAL units (with 4-byte lengths) at the start of the first video sample of a fragment.
fn prepend_to_first_video_sample(fr: &mut Fragment, nals: &[Vec<u8>]) {
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

fn sei(payload_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x06, payload_type, payload.len() as u8];
    v.extend_from_slice(payload);
    v.push(0x80);
    v
}

/// The stream with the video track first: traks, trafs and the `mdat` layout swapped.
fn video_first(g: &[u8]) -> Vec<u8> {
    restamped(
        g,
        |n| {
            let moov = at(n, &["moov"]).kids_mut();
            moov.swap(1, 2);
            // tkhd track IDs follow the trak order.
            for (i, id) in [(0usize, 1u32), (1, 2)] {
                let trak = moov
                    .iter_mut()
                    .filter(|k| &k.typ() == b"trak")
                    .nth(i)
                    .unwrap();
                at(trak.kids_mut(), &["tkhd"]).body_mut()[12..16]
                    .copy_from_slice(&id.to_be_bytes());
            }
        },
        |_, fr| {
            let mut nodes = boxes::parse(&fr.moof);
            let moof = at(&mut nodes, &["moof"]).kids_mut();
            let audio_bytes: u32 = {
                let trun = at(moof, &["traf#0", "trun"]).body_mut();
                let n = u32::from_be_bytes(trun[4..8].try_into().unwrap()) as usize;
                (0..n)
                    .map(|s| {
                        u32::from_be_bytes(
                            trun[12 + 12 * s + 4..12 + 12 * s + 8].try_into().unwrap(),
                        )
                    })
                    .sum()
            };
            moof.swap(1, 2);
            let moof_size = fr.moof.len() as u32;
            let video_bytes = (fr.mdat.len() - 8) as u32 - audio_bytes;
            for (i, (id, offset)) in [(1u32, moof_size + 8), (2, moof_size + 8 + video_bytes)]
                .into_iter()
                .enumerate()
            {
                let traf = moof
                    .iter_mut()
                    .filter(|k| &k.typ() == b"traf")
                    .nth(i)
                    .unwrap();
                at(traf.kids_mut(), &["tfhd"]).body_mut()[4..8].copy_from_slice(&id.to_be_bytes());
                at(traf.kids_mut(), &["trun"]).body_mut()[8..12]
                    .copy_from_slice(&offset.to_be_bytes());
            }
            fr.moof = boxes::serialize(&nodes);
            let audio = fr.mdat[8..8 + audio_bytes as usize].to_vec();
            let video = fr.mdat[8 + audio_bytes as usize..].to_vec();
            let mut mdat = fr.mdat[..8].to_vec();
            mdat.extend(video);
            mdat.extend(audio);
            fr.mdat = mdat;
        },
    )
}

// ---------------------------------------------------------------------------------------------

#[test]
fn positive_structures_the_profile_allows() {
    let g = golden(BASE);
    type Case = (&'static str, Vec<u8>, u8, (u16, u16, u16));
    let cases: Vec<Case> = vec![
        (
            "high_profile_with_scaling_lists",
            restamped(
                &g,
                |n| *at(n, &avcc_path()).body_mut() = avcc(&high_sps(), &PPS, false),
                |_, _| {},
            ),
            100,
            (5, 1, 6),
        ),
        (
            "high_profile_avcc_extension",
            restamped(
                &g,
                |n| *at(n, &avcc_path()).body_mut() = avcc(&high_sps(), &PPS, true),
                |_, _| {},
            ),
            100,
            (5, 1, 6),
        ),
        (
            "baseline_written_by_the_fixture",
            restamped(
                &g,
                |n| *at(n, &avcc_path()).body_mut() = avcc(&baseline_sps(), &PPS, false),
                |_, _| {},
            ),
            66,
            (5, 1, 6),
        ),
        (
            "bt709_label_without_vui_colour",
            patch(
                &golden(BASE29),
                find_box(&golden(BASE29), 0, 2000, b"colr").unwrap() + 12,
                &[0, 1, 0, 1, 0, 1],
            ),
            66,
            (1, 1, 1),
        ),
        ("video_track_first", video_first(&g), 66, (5, 1, 6)),
        (
            "allowed_sei_aud_and_parameter_sets",
            restamped(
                &g,
                |_| {},
                |i, fr| {
                    if i == 0 {
                        let avcc_body = {
                            let off = find_box(&g, 0, head_len(&g), b"avcC").unwrap();
                            g[off + 8..off + get_u32(&g, off) as usize].to_vec()
                        };
                        let sps_len = u16::from_be_bytes([avcc_body[6], avcc_body[7]]) as usize;
                        let sps_nal = avcc_body[8..8 + sps_len].to_vec();
                        prepend_to_first_video_sample(
                            fr,
                            &[
                                vec![0x09, 0x10],
                                sei(6, &[0x84, 0x00]),
                                sei(1, &[0x11, 0x22, 0x33]),
                                sps_nal,
                                PPS.to_vec(),
                            ],
                        );
                    }
                },
            ),
            66,
            (5, 1, 6),
        ),
    ];
    for (name, data, profile, colour) in cases {
        let info = fmp4::check(&data).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(info.profile_idc, profile, "{name}");
        assert_eq!(info.colour, colour, "{name}");
        if name == "video_track_first" {
            assert_eq!(info.video_track, 1);
        }
    }
}

/// The negative corpus: `(name, base golden, mutated input)`; every one must be NON_CANONICAL.
fn corpus() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    corpus_with_recipes()
        .into_iter()
        .map(|(n, b, m, _)| (n, b, m))
        .collect()
}

/// Applies sorted `(offset, removed, inserted)` edits to golden `g` (the base), with the recipe that
/// rebuilds the result.
fn edits(g: &[u8], list: &[(usize, usize, Vec<u8>)]) -> (Vec<u8>, String) {
    let mut m = Vec::new();
    let mut parts = Vec::new();
    let mut at = 0;
    for (off, removed, inserted) in list {
        assert!(*off >= at);
        m.extend_from_slice(&g[at..*off]);
        parts.push(format!("golden:{BASE}[{at}..{off}]"));
        m.extend_from_slice(inserted);
        parts.push(format!("hex:{}", hex::encode(inserted)));
        at = off + removed;
    }
    m.extend_from_slice(&g[at..]);
    parts.push(format!("golden:{BASE}[{at}..]"));
    (m, parts.join(" + "))
}

type Corpus = Vec<(&'static str, &'static str, Vec<u8>, Option<String>)>;

/// The corpus, with the recipe of each case built from an edit list.
fn corpus_with_recipes() -> Corpus {
    let g = golden(BASE);
    let hl = head_len(&g);
    let boxes_top = top_boxes(&g);
    let (moof1, moof1_size) = (boxes_top[2].0, boxes_top[2].1);
    let mdat1 = boxes_top[3].0;
    let moof2 = boxes_top[4].0;
    let mfra = boxes_top.last().unwrap().0;
    let tr1 = trafs(&g[moof1..moof1 + moof1_size]);
    let (atfhd, _, atrun) = (moof1 + tr1[0].0, moof1 + tr1[0].1, moof1 + tr1[0].2);
    let (vtfhd, _vtfdt, vtrun) = (moof1 + tr1[1].0, moof1 + tr1[1].1, moof1 + tr1[1].2);
    let tr2 = trafs(&g[moof2..moof2 + top_boxes(&g)[4].1]);
    let atfdt2 = moof2 + tr2[0].1;
    let vdata = moof1 + get_u32(&g, vtrun + 16) as usize; // the first video sample in the mdat
    let video_sample2 = vdata + get_u32(&g, vtrun + 20 + 4) as usize;
    let sps_off = find_box(&g, 0, hl, b"avcC").unwrap() + 8 + 8; // the SPS NAL in avcC
    let avcc_off = find_box(&g, 0, hl, b"avcC").unwrap();
    let colr_off = find_box(&g, 0, hl, b"colr").unwrap();
    let mut out: Corpus = Vec::new();
    let add = |out: &mut Corpus, name: &'static str, m: Vec<u8>| out.push((name, BASE, m, None));
    // The moov.
    add(&mut out, "ftyp_major_brand", patch(&g, 8, b"mp42"));
    add(
        &mut out,
        "mvhd_timescale_1000",
        with_head(&g, |n| {
            set_body(n, &["moov", "mvhd"], 12, &1000u32.to_be_bytes())
        }),
    );
    add(
        &mut out,
        "mvhd_next_track_4",
        with_head(&g, |n| {
            set_body(n, &["moov", "mvhd"], 96, &4u32.to_be_bytes())
        }),
    );
    add(
        &mut out,
        "tkhd_matrices_differ",
        with_head(&g, |n| {
            set_body(
                n,
                &path(&AUDIO, &["tkhd"]),
                40,
                &[
                    0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0,
                ],
            )
        }),
    );
    add(
        &mut out,
        "tkhd_matrix_45_degrees",
        with_head(&g, |n| {
            for t in [AUDIO, VIDEO] {
                set_body(
                    n,
                    &path(&t, &["tkhd"]),
                    40,
                    &[
                        0, 0, 0xb5, 0x05, 0, 0, 0xb5, 0x05, 0, 0, 0, 0, 0xff, 0xff, 0x4a, 0xfb, 0,
                        0, 0xb5, 0x05,
                    ],
                );
            }
        }),
    );
    add(
        &mut out,
        "tkhd_track_ids_swapped",
        with_head(&g, |n| {
            set_body(n, &path(&AUDIO, &["tkhd"]), 12, &2u32.to_be_bytes());
            set_body(n, &path(&VIDEO, &["tkhd"]), 12, &1u32.to_be_bytes());
        }),
    );
    add(
        &mut out,
        "tkhd_flags_3",
        with_head(&g, |n| set_body(n, &path(&VIDEO, &["tkhd"]), 3, &[3])),
    );
    add(
        &mut out,
        "tkhd_creation_time",
        with_head(&g, |n| {
            set_body(n, &path(&VIDEO, &["tkhd"]), 4, &[0x60, 0, 0, 0])
        }),
    );
    add(
        &mut out,
        "mdhd_timescale_44100",
        with_head(&g, |n| {
            set_body(
                n,
                &path(&AUDIO, &["mdia", "mdhd"]),
                12,
                &44_100u32.to_be_bytes(),
            )
        }),
    );
    add(
        &mut out,
        "mdhd_language_und",
        with_head(&g, |n| {
            set_body(n, &path(&VIDEO, &["mdia", "mdhd"]), 20, &[0x55, 0xc4])
        }),
    );
    add(
        &mut out,
        "hdlr_name",
        with_head(&g, |n| {
            set_body(n, &path(&VIDEO, &["mdia", "hdlr"]), 24, b"GhostHandle")
        }),
    );
    add(
        &mut out,
        "video_only_moov",
        with_head(&g, |n| {
            let moov = at(n, &["moov"]).kids_mut();
            moov.remove(1);
            let mvex = moov.iter_mut().find(|k| &k.typ() == b"mvex").unwrap();
            mvex.kids_mut().remove(0);
        }),
    );
    add(
        &mut out,
        "audio_only_moov",
        with_head(&g, |n| {
            at(n, &["moov"]).kids_mut().remove(2);
        }),
    );
    add(
        &mut out,
        "udta_in_moov",
        with_head(&g, |n| {
            at(n, &["moov"]).kids_mut().push(leaf(
                b"udta",
                b"\0\0\0\x14\xa9xyz\0\x0c\x15\xc7+46.7712+023.6235/",
            ))
        }),
    );
    add(
        &mut out,
        "meta_in_trak",
        with_head(&g, |n| {
            at(n, &VIDEO).kids_mut().push(leaf(b"meta", &[0; 4]))
        }),
    );
    add(
        &mut out,
        "edts_in_trak",
        with_head(&g, |n| {
            at(n, &VIDEO).kids_mut().insert(
                1,
                leaf(
                    b"edts",
                    &[
                        0, 0, 0, 0x1c, b'e', b'l', b's', b't', 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 1, 0, 0,
                    ],
                ),
            )
        }),
    );
    add(
        &mut out,
        "mehd_in_mvex",
        with_head(&g, |n| {
            at(n, &["moov", "mvex"])
                .kids_mut()
                .insert(0, leaf(b"mehd", &[0, 0, 0, 0, 0, 0, 0x10, 0]))
        }),
    );
    add(
        &mut out,
        "uuid_in_stbl",
        with_head(&g, |n| {
            at(n, &path(&VIDEO, &["mdia", "minf", "stbl"]))
                .kids_mut()
                .push(leaf(b"uuid", &[0x11; 20]))
        }),
    );
    add(
        &mut out,
        "avc1_coded_1920x1080",
        with_head(&g, |n| {
            set_body(
                n,
                &path(&VIDEO, &["mdia", "minf", "stbl", "stsd", "avc1"]),
                24,
                &[0x07, 0x80, 0x04, 0x38],
            )
        }),
    );
    add(
        &mut out,
        "avc1_compressor_name",
        with_head(&g, |n| {
            set_body(
                n,
                &path(&VIDEO, &["mdia", "minf", "stbl", "stsd", "avc1"]),
                42,
                b"\x05GHOST",
            )
        }),
    );
    add(
        &mut out,
        "pasp_4_3",
        with_head(&g, |n| {
            *at(
                n,
                &path(&VIDEO, &["mdia", "minf", "stbl", "stsd", "avc1", "pasp"]),
            )
            .body_mut() = vec![0, 0, 0, 4, 0, 0, 0, 3]
        }),
    );
    add(
        &mut out,
        "colr_bt2020",
        patch(&g, colr_off + 12, &[0, 9, 0, 16, 0, 9]),
    );
    add(
        &mut out,
        "colr_full_range",
        patch(&g, colr_off + 18, &[0x80]),
    );
    add(
        &mut out,
        "colr_bt709_against_sps_bt601",
        patch(&g, colr_off + 12, &[0, 1, 0, 1, 0, 1]),
    );
    add(&mut out, "colr_nclc", patch(&g, colr_off + 8, b"nclc"));
    add(&mut out, "sps_level_32", {
        let m = patch(&g, sps_off + 3, &[32]);
        patch(&m, avcc_off + 8 + 3, &[32])
    });
    add(&mut out, "sps_profile_77", {
        let m = patch(&g, sps_off + 1, &[77]);
        patch(&m, avcc_off + 8 + 1, &[77])
    });
    add(
        &mut out,
        "sps_high_444",
        with_sps(
            &g,
            &sps(100, 31, 3, 0, false, 1, (80, 45), 0, Some((5, 1, 6))),
            false,
        ),
    );
    add(
        &mut out,
        "sps_high_10_bit",
        with_sps(
            &g,
            &sps(100, 31, 1, 2, true, 1, (80, 45), 0, Some((5, 1, 6))),
            false,
        ),
    );
    add(
        &mut out,
        "sps_vui_full_range",
        with_sps(
            &g,
            &sps(66, 31, 1, 0, false, 1, (80, 45), 1, Some((5, 1, 6))),
            false,
        ),
    );
    add(
        &mut out,
        "sps_vui_colour_bt709",
        with_sps(
            &g,
            &sps(66, 31, 1, 0, false, 1, (80, 45), 0, Some((1, 1, 1))),
            false,
        ),
    );
    add(
        &mut out,
        "sps_interlaced",
        with_sps(
            &g,
            &sps(66, 31, 1, 0, false, 0, (80, 23), 0, Some((5, 1, 6))),
            false,
        ),
    );
    add(
        &mut out,
        "sps_coded_1920x1088",
        with_sps(
            &g,
            &sps(66, 31, 1, 0, false, 1, (120, 68), 0, Some((5, 1, 6))),
            false,
        ),
    );
    add(
        &mut out,
        "sps_trailing_byte",
        with_sps(
            &g,
            &{
                let mut s = baseline_sps();
                s.push(0x80);
                s
            },
            false,
        ),
    );
    add(
        &mut out,
        "sps_extension_on_baseline",
        with_sps(&g, &baseline_sps(), true),
    );
    add(
        &mut out,
        "avcc_two_sps",
        patch(&g, avcc_off + 8 + 5, &[0xE2]),
    );
    add(
        &mut out,
        "avcc_two_byte_lengths",
        patch(&g, avcc_off + 8 + 4, &[0xFD]),
    );
    add(&mut out, "esds_asc_44100", {
        let esds = find_box(&g, 0, hl, b"esds").unwrap();
        patch(&g, esds + 8 + 26, &[0x12, 0x10])
    });
    add(&mut out, "esds_sl_config_0", {
        let esds = find_box(&g, 0, hl, b"esds").unwrap();
        patch(&g, esds + 8 + 30, &[0x00])
    });
    add(&mut out, "mp4a_mono", {
        let mp4a = find_box(&g, 0, hl, b"mp4a").unwrap();
        patch(&g, mp4a + 8 + 16, &[0, 1])
    });
    add(
        &mut out,
        "stts_one_entry",
        with_head(&g, |n| {
            *at(n, &path(&VIDEO, &["mdia", "minf", "stbl", "stts"])).body_mut() =
                vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0x0b, 0xb8]
        }),
    );
    add(
        &mut out,
        "stss_missing",
        with_head(&g, |n| {
            at(n, &path(&VIDEO, &["mdia", "minf", "stbl"]))
                .kids_mut()
                .pop();
        }),
    );
    add(
        &mut out,
        "dref_external",
        with_head(&g, |n| {
            set_body(
                n,
                &path(&VIDEO, &["mdia", "minf", "dinf", "dref"]),
                19,
                &[0],
            )
        }),
    );
    add(
        &mut out,
        "trex_default_duration",
        with_head(&g, |n| {
            set_body(n, &["moov", "mvex", "trex#0"], 12, &1024u32.to_be_bytes())
        }),
    );
    // The top level and the fragments.
    add(
        &mut out,
        "free_after_moov",
        insert(&g, hl, &[0, 0, 0, 8, b'f', b'r', b'e', b'e']),
    );
    add(
        &mut out,
        "sidx_before_moof",
        insert(&g, hl, &[0, 0, 0, 12, b's', b'i', b'd', b'x', 0, 0, 0, 0]),
    );
    add(
        &mut out,
        "uuid_at_top_level",
        insert(
            &g,
            hl,
            &[
                0, 0, 0, 24, b'u', b'u', b'i', b'd', 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                15, 16,
            ],
        ),
    );
    add(&mut out, "largesize_moof", patch(&g, moof1, &[0, 0, 0, 1]));
    add(&mut out, "to_end_moof", patch(&g, moof1, &[0, 0, 0, 0]));
    add(
        &mut out,
        "mfhd_sequence_2",
        patch(&g, moof1 + 20, &[0, 0, 0, 2]),
    );
    add(
        &mut out,
        "tfhd_default_base_is_moof",
        patch(&g, atfhd + 9, &[0x02, 0x00, 0x01]),
    );
    add(
        &mut out,
        "tfhd_base_offset_wrong",
        patch(&g, vtfhd + 23, &[(g[vtfhd + 23]).wrapping_add(1)]),
    );
    add(&mut out, "traf_without_tfdt", {
        let mut moof = g[moof1..moof1 + moof1_size].to_vec();
        let (t_tfhd, t_tfdt, _) = trafs(&moof)[0];
        let traf = t_tfhd - 8;
        moof.drain(t_tfdt..t_tfdt + 20);
        let traf_size = get_u32(&moof, traf) - 20;
        moof[traf..traf + 4].copy_from_slice(&traf_size.to_be_bytes());
        let moof_size = moof.len() as u32;
        moof[..4].copy_from_slice(&moof_size.to_be_bytes());
        let mut m = g[..moof1].to_vec();
        m.extend(moof);
        m.extend_from_slice(&g[moof1 + moof1_size..]);
        m
    });
    add(&mut out, "tfdt_not_the_running_sum", {
        let v = u64::from_be_bytes(g[atfdt2 + 12..atfdt2 + 20].try_into().unwrap()) + 1;
        patch(&g, atfdt2 + 12, &v.to_be_bytes())
    });
    add(&mut out, "tfdt_version_0", patch(&g, atfdt2 + 8, &[0]));
    add(
        &mut out,
        "trun_composition_offsets",
        patch(&g, vtrun + 10, &[0x0F]),
    );
    add(&mut out, "trun_version_0", patch(&g, vtrun + 8, &[0]));
    add(
        &mut out,
        "trun_data_gap",
        patch(&g, vtrun + 16, &(get_u32(&g, vtrun + 16) + 4).to_be_bytes()),
    );
    add(
        &mut out,
        "first_video_sample_not_sync",
        patch(&g, vtrun + 20 + 8, &[0x01, 0x01, 0x00, 0x00]),
    );
    add(
        &mut out,
        "sync_flag_on_a_non_idr_sample",
        patch(&g, vtrun + 20 + 12 + 8, &[0x02, 0x00, 0x00, 0x00]),
    );
    add(
        &mut out,
        "audio_duration_1023",
        patch(&g, atrun + 20, &1023u32.to_be_bytes()),
    );
    add(
        &mut out,
        "audio_sample_not_sync",
        patch(&g, atrun + 20 + 8, &[0x01, 0x01, 0x00, 0x00]),
    );
    add(
        &mut out,
        "audio_sample_empty",
        patch(&g, atrun + 20 + 4, &0u32.to_be_bytes()),
    );
    add(
        &mut out,
        "audio_sample_1537_bytes",
        patch(&g, atrun + 20 + 4, &1537u32.to_be_bytes()),
    );
    add(
        &mut out,
        "video_sample_zero_duration",
        patch(&g, vtrun + 20, &0u32.to_be_bytes()),
    );
    add(
        &mut out,
        "video_longer_than_max",
        patch(&g, vtrun + 20, &(160_001u32 * 90).to_be_bytes()),
    );
    add(
        &mut out,
        "mdat_size_off_by_one",
        patch(&g, mdat1, &(get_u32(&g, mdat1) + 1).to_be_bytes()),
    );
    add(
        &mut out,
        "nal_type_12_filler",
        patch(&g, vdata + 4, &[0x0c]),
    );
    add(
        &mut out,
        "nal_type_20_extension",
        patch(&g, vdata + 4, &[0x74]),
    );
    add(
        &mut out,
        "nal_forbidden_bit",
        patch(&g, vdata + 4, &[g[vdata + 4] | 0x80]),
    );
    add(
        &mut out,
        "nal_length_beyond_sample",
        patch(&g, vdata, &(get_u32(&g, vdata) + 1).to_be_bytes()),
    );
    add(&mut out, "nal_length_zero", patch(&g, vdata, &[0, 0, 0, 0]));
    add(
        &mut out,
        "idr_in_a_non_sync_sample",
        patch(&g, video_sample2 + 4, &[0x65]),
    );
    // NAL units put in front of the first video sample of the last fragment: its trun row and its
    // mdat size grow, and nothing else moves (each mdat holds the audio samples first, and the mfra
    // names only the moofs' offsets), so the stream is canonical but for the NAL units: a walker
    // without the rule a case names accepts it, and the case's code alone tells. Three edits.
    let mdat2 = boxes_top[5].0;
    let vtrun2 = moof2 + tr2[1].2;
    let vdata2 = moof2 + get_u32(&g, vtrun2 + 16) as usize; // the last fragment's first video sample
    let with_nals = |nals: Vec<Vec<u8>>| {
        let mut bytes = Vec::new();
        for n in &nals {
            bytes.extend_from_slice(&(n.len() as u32).to_be_bytes());
            bytes.extend_from_slice(n);
        }
        let k = bytes.len() as u32;
        let row = vtrun2 + 20 + 4;
        edits(
            &g,
            &[
                (row, 4, (get_u32(&g, row) + k).to_be_bytes().to_vec()),
                (mdat2, 4, (get_u32(&g, mdat2) + k).to_be_bytes().to_vec()),
                (vdata2, 0, bytes),
            ],
        )
    };
    // The construction walks when what it puts in is allowed (an AUD and a recovery-point SEI).
    if let Err(e) = fmp4::check(&with_nals(vec![vec![0x09, 0x10], sei(6, &[0x84, 0x00])]).0) {
        panic!("allowed NAL units in front of the last fragment's first video sample: {e}");
    }
    let add_edited = |out: &mut Corpus, name: &'static str, (m, r): (Vec<u8>, String)| {
        out.push((name, BASE, m, Some(r)))
    };
    add_edited(
        &mut out,
        "sei_user_data_unregistered",
        with_nals(vec![sei(5, &[0x47; 20])]),
    );
    add_edited(
        &mut out,
        "sei_user_data_registered",
        with_nals(vec![sei(4, &[0xb5, 0, 0x31, 0x47, 0x41, 0x39, 0x34])]),
    );
    add_edited(&mut out, "sei_type_7", with_nals(vec![sei(7, &[0x80])]));
    add_edited(
        &mut out,
        "sei_without_trailing_bits",
        with_nals(vec![vec![0x06, 0x06, 0x01, 0x84]]),
    );
    add_edited(
        &mut out,
        "inband_sps_different",
        with_nals(vec![baseline_sps()]),
    );
    add_edited(
        &mut out,
        "inband_pps_different",
        with_nals(vec![vec![0x68, 0xce, 0x01, 0xa8, 0x35, 0xc9]]),
    );
    add_edited(
        &mut out,
        "aud_two_bytes",
        with_nals(vec![vec![0x09, 0x10, 0x00]]),
    );
    add(&mut out, "fragment_above_16_mib", {
        // The last video sample of fragment 1 grown past the bound; the walker refuses at the
        // mdat header, so the input ends there.
        let grow = 16 * 1024 * 1024u32;
        let mut moof = g[moof1..moof1 + moof1_size].to_vec();
        let (_, _, t_trun) = trafs(&moof)[1];
        let count = get_u32(&moof, t_trun + 12) as usize;
        let row = t_trun + 20 + 12 * (count - 1);
        let size = get_u32(&moof, row + 4) + grow;
        moof[row + 4..row + 8].copy_from_slice(&size.to_be_bytes());
        let mut m = g[..moof1].to_vec();
        m.extend(moof);
        m.extend_from_slice(&(get_u32(&g, mdat1) + grow).to_be_bytes());
        m.extend_from_slice(b"mdat");
        m
    });
    add(
        &mut out,
        "mfra_entry_time_wrong",
        patch(&g, mfra + 8 + 24 + 19 + 7, &[g[mfra + 8 + 24 + 19 + 7] ^ 1]),
    );
    add(
        &mut out,
        "mfra_entry_offset_wrong",
        patch(&g, mfra + 8 + 24 + 8 + 7, &[g[mfra + 8 + 24 + 8 + 7] ^ 1]),
    );
    add(
        &mut out,
        "mfra_traf_number_2",
        patch(&g, mfra + 8 + 24 + 16, &[2]),
    );
    add(
        &mut out,
        "mfro_size_wrong",
        patch(&g, g.len() - 1, &[g[g.len() - 1] ^ 1]),
    );
    add(&mut out, "missing_mfra", g[..mfra].to_vec());
    add(&mut out, "byte_after_mfra", insert(&g, g.len(), &[0]));
    add(&mut out, "cut_in_the_last_mdat", g[..moof2 + 900].to_vec());
    add(&mut out, "moov_only", g[..hl].to_vec());
    add(&mut out, "empty", Vec::new());
    out
}

const HEADER: &str = "GHOST canonical fMP4 vectors (Phase 11 design faza11-media.md §8.3, §15.2 item 6; S0-2, S0-3, S0-13, S0-20, S0-22).
Generated and checked by client-core/media/tests/fmp4_vectors.rs (GHOST_WRITE_VECTORS=1 rewrites it).
Replayed by the Rust walker only: the JDK has no second fMP4 walker (Phase 11 design §22.2).
[golden *]: what the walker reports for each committed golden (with its GHOST-built mfra).
[fmp4 *]: an `input` byte recipe (see media_object.txt) over a golden, and the code the walker
must give for the whole content (the reader's mode: the content ends with its mfra).";

#[test]
fn media_fmp4_vectors() {
    let mut text = String::new();
    for l in HEADER.lines() {
        let _ = writeln!(text, "# {l}");
    }
    for (name, data) in goldens(".fmp4") {
        let info = fmp4::check(&data).expect("golden");
        let _ = writeln!(text, "\n[golden {name}]");
        let _ = writeln!(text, "sha256 = {}", hex::encode(sha256(&data)));
        let _ = writeln!(text, "width = {}", info.width);
        let _ = writeln!(text, "height = {}", info.height);
        let _ = writeln!(text, "rotation = {}", info.rotation);
        let _ = writeln!(text, "duration_ms = {}", info.duration_ms);
        let _ = writeln!(text, "colour = {:?}", info.colour);
        let _ = writeln!(text, "profile_idc = {}", info.profile_idc);
        let _ = writeln!(text, "video_track = {}", info.video_track);
        for (i, m) in info.moofs.iter().enumerate() {
            let _ = writeln!(
                text,
                "moof[{i}] = offset {} video_time {}",
                m.offset, m.video_time
            );
        }
    }
    let mut n = 0;
    for (name, base, m, edited) in corpus_with_recipes() {
        let g = golden(base);
        let e = fmp4::check(&m).expect_err(name);
        assert_eq!(e.code(), Code::NonCanonical, "{name}: {e}");
        let r = match edited {
            Some(r) => {
                assert_eq!(recipe(&r), m, "{name}: the recipe rebuilds the input");
                r
            }
            None => diff_recipe(base, &g, &m),
        };
        let _ = writeln!(text, "\n[fmp4 {name}]");
        let _ = writeln!(text, "input = {r}");
        let _ = writeln!(text, "expect = {}", e.code().name());
        n += 1;
    }
    assert!(n >= 70, "{n} cases");
    let path = vectors_dir().join("media_fmp4.txt");
    if writing() {
        std::fs::write(&path, &text).expect("write");
    } else {
        let committed = std::fs::read_to_string(&path)
            .expect("media_fmp4.txt (GHOST_WRITE_VECTORS=1 writes it)")
            .replace("\r\n", "\n");
        assert!(
            committed == text,
            "media_fmp4.txt differs from the regenerated vectors"
        );
    }
}

#[test]
fn every_corpus_case_fails_for_its_own_reason() {
    // Each negative fixture is refused by the rule it names, not by a side effect: the rule text
    // of the refusal is recorded here per case (the vector file keeps only the code).
    let want: &[(&str, &str)] = &[
        ("tkhd_matrices_differ", "two tkhd with different matrices"),
        (
            "tkhd_matrix_45_degrees",
            "a tkhd matrix other than 0, 90, 180 or 270 degrees",
        ),
        (
            "video_only_moov",
            "a moov is exactly mvhd, trak, trak, mvex",
        ),
        (
            "avc1_coded_1920x1080",
            "an avc1 entry that is not coded 1 280 × 720",
        ),
        ("colr_bt2020", "a colr other than (5, 1, 6) or (1, 1, 1)"),
        (
            "colr_bt709_against_sps_bt601",
            "an SPS colour description other than the colr box's",
        ),
        ("sps_level_32", "an SPS level_idc other than 31"),
        (
            "sps_profile_77",
            "an SPS profile other than 66 (Baseline) or 100 (High)",
        ),
        ("sps_high_444", "chroma_format_idc is not 1"),
        ("sps_high_10_bit", "a High-profile SPS that is not 8-bit"),
        ("sps_vui_full_range", "video_full_range_flag 1"),
        ("sps_interlaced", "frame_mbs_only_flag 0"),
        (
            "sps_coded_1920x1088",
            "an SPS coded size other than 1 280 × 720",
        ),
        ("traf_without_tfdt", "a traf is exactly tfhd, tfdt, trun"),
        (
            "tfdt_not_the_running_sum",
            "a tfdt that is not version 1 with the running sum",
        ),
        (
            "trun_composition_offsets",
            "a trun other than version 1, flags 0x701",
        ),
        (
            "first_video_sample_not_sync",
            "first video sample is not a sync sample",
        ),
        (
            "sync_flag_on_a_non_idr_sample",
            "a sync flag that does not match",
        ),
        (
            "idr_in_a_non_sync_sample",
            "a sync flag that does not match",
        ),
        (
            "fragment_above_16_mib",
            "a fragment (moof + mdat) above 16 MiB",
        ),
        ("mfra_entry_time_wrong", "an mfra other than GHOST's"),
        ("mfra_traf_number_2", "an mfra other than GHOST's"),
        (
            "sei_user_data_unregistered",
            "an SEI payload type other than 0, 1 or 6",
        ),
        (
            "inband_sps_different",
            "an in-band SPS or PPS other than the avcC's",
        ),
        (
            "nal_type_12_filler",
            "a NAL unit type outside 1, 5, 6, 7, 8, 9",
        ),
        ("udta_in_moov", "a moov is exactly mvhd, trak, trak, mvex"),
        ("free_after_moov", "a top-level box outside"),
        ("largesize_moof", "a box whose size is below 8"),
        ("video_longer_than_max", "a video longer than VIDEO_MAX_MS"),
        ("missing_mfra", "ends inside a box or before"),
        ("byte_after_mfra", "bytes after the mfra"),
    ];
    let all = corpus();
    for (name, rule) in want {
        let (_, _, m) = all
            .iter()
            .find(|(n, _, _)| n == name)
            .unwrap_or_else(|| panic!("{name}"));
        let e = fmp4::check(m).expect_err(name);
        assert!(
            e.rule().contains(rule),
            "{name}: refused for '{}', not '{rule}'",
            e.rule()
        );
    }
}
