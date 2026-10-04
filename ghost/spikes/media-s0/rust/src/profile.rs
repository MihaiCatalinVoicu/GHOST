//! The canonical fMP4 profile as corrected after the S0 review (2026-10-04; S0-2, S0-3, S0-13,
//! S0-20, S0-22 of `docs/design/faza11-s0-evidence.md`), as a checker: [`check`] returns every
//! violation of one file, and an empty list means the file is canonical. Evidence tooling: it
//! states the rules once, in code, so that the goldens of `ghost/protocol/test-vectors/
//! media-goldens` are checked against them rather than described; `ghost-client-media`'s walker
//! (S1) is written under review, not copied from here.

use crate::mp4::{self, BoxNode};

fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}
fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn be64(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(b[o..o + 8].try_into().expect("8"))
}

/// Allowed AVC profiles (S0-22): Baseline (66, as the emulators' encoders write it with
/// constraint_set0/1) and High (100, which Media3 1.11.1 requests on API 29+ from any encoder that
/// supports it, whatever profile GHOST asks for); level 3.1 only.
pub const ALLOWED_PROFILES: [u8; 2] = [66, 100];
pub const LEVEL_IDC: u8 = 31;
/// The canonical colour labels (S0-13, revised in the review pass): `nclx` (primaries, transfer,
/// matrix) with limited range, BT.709 or BT.601 as Media3 1.11.1 writes them; the label must be the
/// matrix the encoder really coded, which a per-encoder calibration decides (design §8.3).
pub const COLOUR_LABELS: [(u16, u16, u16); 2] = [(1, 1, 1), (5, 1, 6)];

struct Track {
    id: u32,
    handler: [u8; 4],
    matrix_rotation: i32,
}

/// Every violation of the profile in `data`, or an empty list.
pub fn check(data: &[u8]) -> Vec<String> {
    let mut v = Vec::new();
    let top = match mp4::parse_boxes(data, 0, data.len()) {
        Ok(t) => t,
        Err(e) => return vec![format!("unparsable: {e}")],
    };
    // 1. Top level: ftyp, moov, (moof, mdat) pairs, mfra; nothing else.
    let types: Vec<String> = top.iter().map(|b| b.type_str()).collect();
    let mut ok_order = types.len() >= 5 && types[0] == "ftyp" && types[1] == "moov" && types.last().map(String::as_str) == Some("mfra");
    if ok_order {
        let mid = &types[2..types.len() - 1];
        ok_order = !mid.is_empty() && mid.len() % 2 == 0 && mid.chunks(2).all(|p| p[0] == "moof" && p[1] == "mdat");
    }
    if !ok_order {
        v.push(format!("top level is not ftyp, moov, (moof, mdat)+, mfra: {types:?}"));
    }
    if let Some(ftyp) = top.first().filter(|b| &b.typ == b"ftyp") {
        let b = ftyp.body(data);
        let compat: Vec<&[u8]> = b[8..].chunks(4).collect();
        if &b[0..4] != b"isom" || be32(b, 4) != 131_072 || compat != vec![&b"isom"[..], &b"iso2"[..], &b"mp41"[..]] {
            v.push("ftyp is not (isom, 131072, isom iso2 mp41)".into());
        }
    }
    let Some(moov) = top.iter().find(|b| &b.typ == b"moov") else {
        v.push("no moov".into());
        return v;
    };
    // 2. moov = mvhd, two trak, mvex.
    let mt: Vec<String> = moov.children.iter().map(|b| b.type_str()).collect();
    if mt != ["mvhd", "trak", "trak", "mvex"] {
        v.push(format!("moov children {mt:?}"));
    }
    if let Some(mvhd) = moov.find(b"mvhd") {
        let b = mvhd.body(data);
        if b[0] != 0 || be32(b, 4) != 0 || be32(b, 8) != 0 || be32(b, 12) != 10_000 || be32(b, 16) != 0 {
            v.push("mvhd is not v0 with times 0, timescale 10000, duration 0".into());
        }
    }
    let mut tracks = Vec::new();
    for trak in moov.find_all(b"trak") {
        match check_trak(data, trak, &mut v) {
            Some(t) => tracks.push(t),
            None => v.push("trak unreadable".into()),
        }
    }
    let handlers: Vec<[u8; 4]> = tracks.iter().map(|t| t.handler).collect();
    if !(handlers.contains(b"soun") && handlers.contains(b"vide") && tracks.len() == 2) {
        v.push(format!("tracks are not one soun and one vide: {:?}", handlers.iter().map(|h| String::from_utf8_lossy(h).to_string()).collect::<Vec<_>>()));
    }
    let mut ids: Vec<u32> = tracks.iter().map(|t| t.id).collect();
    ids.sort_unstable();
    if ids != [1, 2] {
        v.push(format!("track IDs {ids:?}, not 1 and 2"));
    }
    if tracks.len() == 2 && tracks[0].matrix_rotation != tracks[1].matrix_rotation {
        v.push("the two tkhd matrices differ (Media3 writes the file's orientation into both)".into());
    }
    if let Some(mvex) = moov.find(b"mvex") {
        let trex = mvex.find_all(b"trex");
        if trex.len() != 2 || mvex.children.len() != 2 {
            v.push("mvex is not two trex".into());
        }
        for t in trex {
            let b = t.body(data);
            if be32(b, 8) != 1 || be32(b, 12) != 0 || be32(b, 16) != 0 || be32(b, 20) != 0 {
                v.push("trex defaults are not (1, 0, 0, 0)".into());
            }
        }
    }
    let video_id = tracks.iter().find(|t| &t.handler == b"vide").map(|t| t.id).unwrap_or(0);
    // 3. Fragments: mfhd + one traf per track; traf = tfhd (0x1, base = moof offset) + tfdt (v1,
    //    the running sum of that track's trun durations) + trun (0x701, data inside its mdat).
    let mut decode_time: std::collections::BTreeMap<u32, u64> = Default::default();
    let mut moof_video_times = Vec::new();
    let mut seq_expected = 1u32;
    let moofs: Vec<&BoxNode> = top.iter().filter(|b| &b.typ == b"moof").collect();
    for moof in &moofs {
        let ct: Vec<String> = moof.children.iter().map(|b| b.type_str()).collect();
        if ct != ["mfhd", "traf", "traf"] {
            v.push(format!("moof at {} children {ct:?}", moof.offset));
        }
        if let Some(mfhd) = moof.find(b"mfhd") {
            if be32(mfhd.body(data), 4) != seq_expected {
                v.push(format!("mfhd sequence at {} is not {seq_expected}", moof.offset));
            }
        }
        seq_expected += 1;
        let mdat = top.iter().find(|b| b.offset == moof.offset + moof.size && &b.typ == b"mdat");
        for traf in moof.find_all(b"traf") {
            let tt: Vec<String> = traf.children.iter().map(|b| b.type_str()).collect();
            if tt != ["tfhd", "tfdt", "trun"] {
                v.push(format!("traf at {} is {tt:?}, not tfhd, tfdt, trun", traf.offset));
                continue;
            }
            let tfhd = traf.find(b"tfhd").expect("checked").body(data);
            let flags = be32(tfhd, 0) & 0xFF_FFFF;
            let track = be32(tfhd, 4);
            if flags != 0x1 || be64(tfhd, 8) != moof.offset as u64 {
                v.push(format!("tfhd of track {track} at {}: flags {flags:#x} or base_data_offset is not the moof's offset", traf.offset));
            }
            let tfdt = traf.find(b"tfdt").expect("checked").body(data);
            let want = *decode_time.get(&track).unwrap_or(&0);
            if tfdt[0] != 1 || be64(tfdt, 4) != want {
                v.push(format!("tfdt of track {track} in moof {} is not v1 = {want}", moof.offset));
            }
            if track == video_id {
                moof_video_times.push((want, moof.offset as u64));
            }
            let trun_box = traf.find(b"trun").expect("checked");
            let trun = mp4::parse_trun(trun_box.body(data));
            if trun.flags != 0x701 {
                v.push(format!("trun of track {track} has flags {:#x}, not 0x701 (no composition offsets)", trun.flags));
            }
            let sum: u64 = trun.samples.iter().map(|s| s.duration.unwrap_or(0) as u64).sum();
            let bytes: u64 = trun.samples.iter().map(|s| s.size.unwrap_or(0) as u64).sum();
            decode_time.insert(track, want + sum);
            if let (Some(off), Some(mdat)) = (trun.data_offset, mdat) {
                let start = moof.offset as i64 + off as i64;
                let lo = (mdat.offset + mdat.header) as i64;
                let hi = (mdat.offset + mdat.size) as i64;
                if start < lo || start + bytes as i64 > hi {
                    v.push(format!("trun of track {track} at {} points outside its mdat", traf.offset));
                }
            } else {
                v.push(format!("trun of track {track} without data_offset or mdat"));
            }
            if track == video_id {
                if let Some(first) = trun.samples.first() {
                    if !first.flags.map(mp4::is_sync).unwrap_or(false) {
                        v.push(format!("video fragment at {} does not start with a sync sample", moof.offset));
                    }
                }
            }
        }
    }
    // 4. mfra: one tfra (v1) for the video track, one entry per moof with the moof's video tfdt
    //    and offset, then mfro.
    if let Some(mfra) = top.iter().find(|b| &b.typ == b"mfra") {
        let ct: Vec<String> = mfra.children.iter().map(|b| b.type_str()).collect();
        if ct != ["tfra", "mfro"] {
            v.push(format!("mfra children {ct:?}"));
        }
        if let Some(tfra) = mfra.find(b"tfra") {
            let body = tfra.body(data);
            let (track, entries) = mp4::parse_tfra(body);
            if body[0] != 1 || track != video_id || entries != moof_video_times {
                v.push(format!("tfra (v{}, track {track}) entries {entries:?} are not the moofs' video tfdt and offsets {moof_video_times:?}", body[0]));
            }
        }
        if let Some(mfro) = mfra.find(b"mfro") {
            if be32(mfro.body(data), 4) as usize != mfra.size {
                v.push("mfro does not give the mfra's size".into());
            }
        }
    }
    v
}

fn check_trak(data: &[u8], trak: &BoxNode, v: &mut Vec<String>) -> Option<Track> {
    let ct: Vec<String> = trak.children.iter().map(|b| b.type_str()).collect();
    if ct != ["tkhd", "mdia"] {
        v.push(format!("trak children {ct:?}"));
    }
    let tkhd = trak.find(b"tkhd")?.body(data);
    let id = be32(tkhd, 12);
    let matrix: Vec<i32> = (0..9).map(|i| be32(tkhd, 40 + 4 * i) as i32).collect();
    let rotation = mp4::rotation_of(&matrix);
    if tkhd[0] != 0 || be32(tkhd, 0) & 0xFF_FFFF != 7 || be32(tkhd, 4) != 0 || be32(tkhd, 8) != 0 || be32(tkhd, 20) != 0 || rotation < 0 {
        v.push(format!("tkhd of track {id} is not v0, flags 7, times 0, duration 0, a 0/90/180/270 matrix"));
    }
    let mdia = trak.find(b"mdia")?;
    let mt: Vec<String> = mdia.children.iter().map(|b| b.type_str()).collect();
    if mt != ["mdhd", "hdlr", "minf"] {
        v.push(format!("mdia of track {id} is {mt:?}"));
    }
    let hdlr = mdia.find(b"hdlr")?.body(data);
    let handler: [u8; 4] = hdlr[8..12].try_into().ok()?;
    let name = String::from_utf8_lossy(&hdlr[24..]).trim_end_matches('\0').to_string();
    let mdhd = mdia.find(b"mdhd")?.body(data);
    let (want_ts, want_name, want_media) = if &handler == b"soun" { (48_000, "SoundHandle", b"smhd") } else { (90_000, "VideoHandle", b"vmhd") };
    if mdhd[0] != 0 || be32(mdhd, 4) != 0 || be32(mdhd, 8) != 0 || be32(mdhd, 12) != want_ts || be32(mdhd, 16) != 0 {
        v.push(format!("mdhd of track {id} is not v0, times 0, timescale {want_ts}, duration 0"));
    }
    if name != want_name || !(&handler == b"soun" || &handler == b"vide") {
        v.push(format!("hdlr of track {id} is {:?} {name:?}", String::from_utf8_lossy(&handler)));
    }
    let minf = mdia.find(b"minf")?;
    let it: Vec<String> = minf.children.iter().map(|b| b.type_str()).collect();
    if it != [String::from_utf8_lossy(want_media).to_string(), "dinf".into(), "stbl".into()] {
        v.push(format!("minf of track {id} is {it:?}"));
    }
    let stbl = minf.find(b"stbl")?;
    let st: Vec<String> = stbl.children.iter().map(|b| b.type_str()).collect();
    let want_st: Vec<&str> = if &handler == b"vide" { vec!["stsd", "stts", "stsz", "stsc", "stco", "stss"] } else { vec!["stsd", "stts", "stsz", "stsc", "stco"] };
    if st != want_st {
        v.push(format!("stbl of track {id} is {st:?}"));
    }
    let stsd = stbl.find(b"stsd")?;
    if stsd.children.len() != 1 {
        v.push(format!("stsd of track {id} has {} entries", stsd.children.len()));
    }
    let entry = stsd.children.first()?;
    let eb = entry.body(data);
    if &handler == b"soun" {
        let esds = entry.find(b"esds").map(|e| e.body(data));
        let asc = esds.and_then(mp4::parse_esds_asc);
        if &entry.typ != b"mp4a" || be16(eb, 16) != 2 || be16(eb, 18) != 16 || (be32(eb, 24) >> 16) != 48_000 || asc.as_deref() != Some(&[0x11, 0x90][..]) || entry.children.len() != 1 {
            v.push(format!("audio sample entry is not mp4a + esds, AAC-LC 48 kHz stereo (asc {:?})", asc.map(|a| crate::hex(&a))));
        }
    } else {
        let (w, h) = (be16(eb, 24), be16(eb, 26));
        let et: Vec<String> = entry.children.iter().map(|b| b.type_str()).collect();
        if &entry.typ != b"avc1" || (w, h) != (1280, 720) || et != ["avcC", "pasp", "colr"] {
            v.push(format!("video sample entry {} {w}x{h} {et:?} is not avc1 1280x720 with avcC, pasp, colr", entry.type_str()));
        }
        if let Some(pasp) = entry.find(b"pasp") {
            // Media3 1.11.1 writes square pixels as 65536:65536.
            let p = pasp.body(data);
            if be32(p, 0) != 65_536 || be32(p, 4) != 65_536 {
                v.push(format!("pasp is {}:{}, not 65536:65536", be32(p, 0), be32(p, 4)));
            }
        }
        // Review pass (2026-10-04, S0-13): the label must describe the pixels, and the encoder picks
        // the matrix (API 35's follows the request, API 29's always codes BT.601), so two labels are
        // canonical: BT.709 limited (1, 1, 1) and BT.601 limited as Media3 writes it (5, 1, 6).
        let mut colr_triple: Option<(u16, u16, u16)> = None;
        if let Some(colr) = entry.find(b"colr") {
            let c = colr.body(data);
            let ok = c.len() == 11 && &c[0..4] == b"nclx" && c[10] == 0 && {
                let t = (be16(c, 4), be16(c, 6), be16(c, 8));
                colr_triple = Some(t);
                COLOUR_LABELS.contains(&t)
            };
            if !ok {
                v.push(format!("colr is {} , not nclx (1, 1, 1) or (5, 1, 6), limited", crate::hex(c)));
            }
        }
        if let Some(avcc) = entry.find(b"avcC").and_then(|a| mp4::parse_avcc(a.body(data))) {
            if !ALLOWED_PROFILES.contains(&avcc.profile) || avcc.level != LEVEL_IDC || avcc.nal_len != 4 || avcc.sps.len() != 1 || avcc.pps.len() != 1 {
                v.push(format!("avcC profile {} level {} nal_len {} sps {} pps {}: not profile 66/100, level 3.1, 4-byte lengths, one SPS and one PPS", avcc.profile, avcc.level, avcc.nal_len, avcc.sps.len(), avcc.pps.len()));
            }
            if let Some(sps) = avcc.sps.first() {
                let d = mp4::describe_sps(sps);
                if d.contains("scaling_matrix=present") || d.contains("(truncated)") {
                    v.push(format!("SPS not walkable to its VUI: {d}"));
                }
                if d.contains("chroma_format=") && !d.contains("chroma_format=1 bit_depth=8/8") {
                    v.push(format!("SPS is not 4:2:0 8-bit: {d}"));
                }
                // The VUI either has no colour description or exactly the `colr` box's values.
                let vui_ok = match colr_triple {
                    Some((p, t, m)) => !d.contains("colour=") || d.contains(&format!("colour=({p},{t},{m})")),
                    None => !d.contains("colour="),
                };
                if !vui_ok || d.contains("full_range=1") {
                    v.push(format!("SPS VUI colour is not absent or the colr values, limited range: {d}"));
                }
                if !d.contains("frame_mbs_only=1") {
                    v.push(format!("SPS is not frame_mbs_only: {d}"));
                }
            }
        } else {
            v.push("avcC unreadable".into());
        }
    }
    Some(Track { id, handler, matrix_rotation: rotation })
}
