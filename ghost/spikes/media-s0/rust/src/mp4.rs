//! ISO-BMFF walker for the Media3 outputs and the video sources the probes made on the emulators:
//! the box inventory (V-M3 goldens), per-track sample entries (V-M24), fragments and sync samples
//! (V-M2), H.264 NAL and SEI payload types (V-M12, V-M17), AAC first elements and canaries
//! (V-M12, V-M17), and the GHOST `mfra` index of design §8.3.

use std::collections::BTreeMap;

/// One box: type, absolute offset, header size, total size, and children when it is a container.
#[derive(Clone, Debug)]
pub struct BoxNode {
    pub typ: [u8; 4],
    pub offset: usize,
    pub header: usize,
    pub size: usize,
    pub children: Vec<BoxNode>,
}

impl BoxNode {
    pub fn type_str(&self) -> String {
        self.typ
            .iter()
            .map(|&c| {
                if (0x20..0x7f).contains(&c) {
                    c as char
                } else {
                    '?'
                }
            })
            .collect()
    }
    pub fn body<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.offset + self.header..self.offset + self.size]
    }
    pub fn find(&self, t: &[u8; 4]) -> Option<&BoxNode> {
        self.children.iter().find(|c| &c.typ == t)
    }
    pub fn find_all<'a>(&'a self, t: &[u8; 4]) -> Vec<&'a BoxNode> {
        self.children.iter().filter(|c| &c.typ == t).collect()
    }
    pub fn path(&self, p: &[&[u8; 4]]) -> Option<&BoxNode> {
        let mut cur = self;
        for t in p {
            cur = cur.find(t)?;
        }
        Some(cur)
    }
}

fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}
fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn be64(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(b[o..o + 8].try_into().expect("8"))
}

const CONTAINERS: &[&[u8; 4]] = &[
    b"moov", b"trak", b"mdia", b"minf", b"stbl", b"mvex", b"moof", b"traf", b"mfra", b"udta",
    b"edts", b"dinf", b"ilst", b"sinf", b"schi",
];

/// Parses the boxes of `data[start..end]`; `meta` is handled as a full box or a QuickTime box.
pub fn parse_boxes(data: &[u8], start: usize, end: usize) -> Result<Vec<BoxNode>, String> {
    let mut out = Vec::new();
    let mut p = start;
    while p < end {
        if end - p < 8 {
            return Err(format!("{} trailing bytes at {p}", end - p));
        }
        let mut size = be32(data, p) as usize;
        let typ: [u8; 4] = data[p + 4..p + 8].try_into().expect("4");
        let mut header = 8;
        if size == 1 {
            if end - p < 16 {
                return Err("truncated largesize".into());
            }
            size = be64(data, p + 8) as usize;
            header = 16;
        } else if size == 0 {
            size = end - p;
        }
        if &typ == b"uuid" {
            header += 16;
        }
        if size < header || p + size > end {
            return Err(format!(
                "box {:?} at {p} has size {size} beyond {end}",
                String::from_utf8_lossy(&typ)
            ));
        }
        let mut node = BoxNode {
            typ,
            offset: p,
            header,
            size,
            children: Vec::new(),
        };
        if CONTAINERS.contains(&&typ) {
            node.children = parse_boxes(data, p + header, p + size)?;
        } else if &typ == b"meta" {
            // ISO full box (version/flags) or QuickTime (children directly): try both.
            let full = parse_boxes(data, p + header + 4, p + size);
            match full {
                Ok(c) if !c.is_empty() => {
                    node.header += 4;
                    node.children = c;
                }
                _ => node.children = parse_boxes(data, p + header, p + size).unwrap_or_default(),
            }
        } else if &typ == b"stsd" {
            let body_start = p + header + 8;
            node.header += 8;
            node.children = parse_boxes(data, body_start, p + size)?;
            for entry in node.children.iter_mut() {
                let skip = match &entry.typ {
                    b"avc1" | b"avc3" | b"hvc1" | b"hev1" | b"mp4v" | b"vp09" | b"av01"
                    | b"encv" => 78,
                    b"mp4a" | b"enca" => 28,
                    _ => usize::MAX,
                };
                if skip != usize::MAX && entry.size >= entry.header + skip {
                    let cs = entry.offset + entry.header + skip;
                    entry.children =
                        parse_boxes(data, cs, entry.offset + entry.size).unwrap_or_default();
                }
            }
        }
        out.push(node);
        p += size;
    }
    Ok(out)
}

/// A readable tree with the fields that matter for the canonical profile.
pub fn describe_tree(data: &[u8], nodes: &[BoxNode], depth: usize, out: &mut String) {
    for n in nodes {
        let b = n.body(data);
        let mut d = String::new();
        match &n.typ {
            b"ftyp" if b.len() >= 8 => {
                let brands: Vec<String> = b[8..]
                    .chunks(4)
                    .map(|c| String::from_utf8_lossy(c).to_string())
                    .collect();
                d = format!(
                    "major={} minor={} compat={:?}",
                    String::from_utf8_lossy(&b[..4]),
                    be32(b, 4),
                    brands
                );
            }
            b"mvhd" | b"mdhd" => {
                let v = b[0];
                let (c, m, ts, dur, rest) = if v == 1 {
                    (be64(b, 4), be64(b, 12), be32(b, 20), be64(b, 24), 32)
                } else {
                    (
                        be32(b, 4) as u64,
                        be32(b, 8) as u64,
                        be32(b, 12),
                        be32(b, 16) as u64,
                        20,
                    )
                };
                d = format!("v{v} creation={c} modification={m} timescale={ts} duration={dur}");
                if &n.typ == b"mdhd" && b.len() >= rest + 2 {
                    let lang = be16(b, rest);
                    let l: String = [(lang >> 10) & 31, (lang >> 5) & 31, lang & 31]
                        .iter()
                        .map(|&x| (x as u8 + 0x60) as char)
                        .collect();
                    d.push_str(&format!(" language={l}"));
                } else if b.len() >= rest + 80 {
                    d.push_str(&format!(" next_track_ID={}", be32(b, rest + 76)));
                }
            }
            b"tkhd" => {
                let v = b[0];
                let flags = be32(b, 0) & 0xFFFFFF;
                let (c, m, id, dur, rest) = if v == 1 {
                    (be64(b, 4), be64(b, 12), be32(b, 20), be64(b, 28), 36)
                } else {
                    (
                        be32(b, 4) as u64,
                        be32(b, 8) as u64,
                        be32(b, 12),
                        be32(b, 20) as u64,
                        24,
                    )
                };
                let matrix: Vec<i32> = (0..9).map(|i| be32(b, rest + 16 + 4 * i) as i32).collect();
                let w = be32(b, rest + 52) as f64 / 65536.0;
                let h = be32(b, rest + 56) as f64 / 65536.0;
                d = format!(
                    "v{v} flags={flags:#x} creation={c} modification={m} track_ID={id} duration={dur} {w}x{h} matrix={matrix:?} rotation={}",
                    rotation_of(&matrix)
                );
            }
            b"hdlr" if b.len() >= 24 => {
                let name: String = b[24..]
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as char)
                    .collect();
                d = format!(
                    "handler={} name=\"{name}\"",
                    String::from_utf8_lossy(&b[8..12])
                );
            }
            b"avc1" | b"avc3" | b"hvc1" | b"hev1" => {
                if b.len() >= 78 {
                    d = format!("{}x{} compressor=\"{}\"", be16(b, 24), be16(b, 26), {
                        let l = b[42] as usize;
                        String::from_utf8_lossy(&b[43..43 + l.min(31)]).to_string()
                    });
                }
            }
            b"mp4a" if b.len() >= 28 => {
                d = format!(
                    "channels={} samplesize={} samplerate={}",
                    be16(b, 16),
                    be16(b, 18),
                    be32(b, 24) >> 16
                );
            }
            b"avcC" => {
                if let Some(c) = parse_avcc(b) {
                    d = format!(
                        "profile={} compat={:#04x} level={} nal_len={} sps={} pps={}",
                        c.profile,
                        c.compat,
                        c.level,
                        c.nal_len,
                        c.sps
                            .iter()
                            .map(|s| crate::hex(s))
                            .collect::<Vec<_>>()
                            .join(","),
                        c.pps
                            .iter()
                            .map(|s| crate::hex(s))
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                    for s in &c.sps {
                        d.push_str(&format!(" sps_parsed=[{}]", describe_sps(s)));
                    }
                }
            }
            b"esds" => {
                if let Some(asc) = parse_esds_asc(b) {
                    d = format!("asc={} {}", crate::hex(&asc), describe_asc(&asc));
                }
            }
            b"colr" | b"pasp" | b"btrt" => d = crate::hex(&b[..b.len().min(32)]),
            b"trex" => {
                d = format!(
                    "track_ID={} desc={} dur={} size={} flags={:#010x}",
                    be32(b, 4),
                    be32(b, 8),
                    be32(b, 12),
                    be32(b, 16),
                    be32(b, 20)
                )
            }
            b"mfhd" => d = format!("sequence={}", be32(b, 4)),
            b"tfhd" => d = describe_tfhd(b),
            b"tfdt" => {
                let v = b[0];
                d = format!(
                    "v{v} base_media_decode_time={}",
                    if v == 1 {
                        be64(b, 4)
                    } else {
                        be32(b, 4) as u64
                    }
                );
            }
            b"trun" => {
                let t = parse_trun(b);
                let durs: u64 = t
                    .samples
                    .iter()
                    .map(|s| s.duration.unwrap_or(0) as u64)
                    .sum();
                d = format!(
                    "flags={:#x} samples={} data_offset={:?} first_flags={:?} sum_duration={} first_sync={}",
                    t.flags,
                    t.samples.len(),
                    t.data_offset,
                    t.first_sample_flags.map(|f| format!("{f:#010x}")),
                    durs,
                    t.samples.first().map(|s| s.flags.map(is_sync)).unwrap_or(None).map(|x| x.to_string()).unwrap_or("?".into())
                );
            }
            b"tfra" => {
                let (track, entries) = parse_tfra(b);
                d = format!("track_ID={track} entries={}", entries.len());
            }
            b"mfro" => d = format!("mfra_size={}", be32(b, 4)),
            b"mdat" => d = format!("payload={}", b.len()),
            b"uuid" => {
                d = format!(
                    "usertype={}",
                    crate::hex(&data[n.offset + 8..n.offset + 24])
                )
            }
            _ => {}
        }
        out.push_str(&format!(
            "{}{} @{} size={} {}\n",
            "  ".repeat(depth),
            n.type_str(),
            n.offset,
            n.size,
            d
        ));
        describe_tree(data, &n.children, depth + 1, out);
    }
}

/// Rotation in degrees from a `tkhd` matrix (the four values Media3 and MPEG4Writer write).
pub fn rotation_of(m: &[i32]) -> i32 {
    let one = 0x10000;
    match (m[0], m[1], m[3], m[4]) {
        (a, 0, 0, d) if a == one && d == one => 0,
        (0, b, c, 0) if b == one && c == -one => 90,
        (a, 0, 0, d) if a == -one && d == -one => 180,
        (0, b, c, 0) if b == -one && c == one => 270,
        _ => -1,
    }
}

fn describe_tfhd(b: &[u8]) -> String {
    let flags = be32(b, 0) & 0xFFFFFF;
    let mut o = 8;
    let mut d = format!("flags={flags:#x} track_ID={}", be32(b, 4));
    if flags & 0x1 != 0 {
        d.push_str(&format!(" base_data_offset={}", be64(b, o)));
        o += 8;
    }
    if flags & 0x2 != 0 {
        d.push_str(&format!(" desc={}", be32(b, o)));
        o += 4;
    }
    if flags & 0x8 != 0 {
        d.push_str(&format!(" default_duration={}", be32(b, o)));
        o += 4;
    }
    if flags & 0x10 != 0 {
        d.push_str(&format!(" default_size={}", be32(b, o)));
        o += 4;
    }
    if flags & 0x20 != 0 {
        d.push_str(&format!(" default_flags={:#010x}", be32(b, o)));
    }
    d
}

/// `sample_is_non_sync_sample` is bit 16 of the sample flags.
pub fn is_sync(flags: u32) -> bool {
    flags & 0x0001_0000 == 0
}

#[derive(Clone, Debug, Default)]
pub struct TrunSample {
    pub duration: Option<u32>,
    pub size: Option<u32>,
    pub flags: Option<u32>,
    pub cto: Option<i32>,
}

#[derive(Clone, Debug, Default)]
pub struct Trun {
    pub flags: u32,
    pub data_offset: Option<i32>,
    pub first_sample_flags: Option<u32>,
    pub samples: Vec<TrunSample>,
}

pub fn parse_trun(b: &[u8]) -> Trun {
    let flags = be32(b, 0) & 0xFFFFFF;
    let count = be32(b, 4) as usize;
    let mut o = 8;
    let mut t = Trun {
        flags,
        ..Default::default()
    };
    if flags & 0x1 != 0 {
        t.data_offset = Some(be32(b, o) as i32);
        o += 4;
    }
    if flags & 0x4 != 0 {
        t.first_sample_flags = Some(be32(b, o));
        o += 4;
    }
    for i in 0..count {
        let mut s = TrunSample::default();
        if flags & 0x100 != 0 {
            s.duration = Some(be32(b, o));
            o += 4;
        }
        if flags & 0x200 != 0 {
            s.size = Some(be32(b, o));
            o += 4;
        }
        if flags & 0x400 != 0 {
            s.flags = Some(be32(b, o));
            o += 4;
        } else if i == 0 {
            s.flags = t.first_sample_flags;
        }
        if flags & 0x800 != 0 {
            s.cto = Some(be32(b, o) as i32);
            o += 4;
        }
        t.samples.push(s);
    }
    t
}

/// `(track_ID, [(time, moof_offset)])` of a `tfra`.
pub fn parse_tfra(b: &[u8]) -> (u32, Vec<(u64, u64)>) {
    let v = b[0];
    let track = be32(b, 4);
    let lens = be32(b, 8);
    let (lt, lr, ls) = (((lens >> 4) & 3) + 1, ((lens >> 2) & 3) + 1, (lens & 3) + 1);
    let n = be32(b, 12) as usize;
    let mut o = 16;
    let mut out = Vec::new();
    for _ in 0..n {
        let (time, moof) = if v == 1 {
            let r = (be64(b, o), be64(b, o + 8));
            o += 16;
            r
        } else {
            let r = (be32(b, o) as u64, be32(b, o + 4) as u64);
            o += 8;
            r
        };
        o += (lt + lr + ls) as usize;
        out.push((time, moof));
    }
    (track, out)
}

#[derive(Clone, Debug)]
pub struct AvcC {
    pub profile: u8,
    pub compat: u8,
    pub level: u8,
    pub nal_len: usize,
    pub sps: Vec<Vec<u8>>,
    pub pps: Vec<Vec<u8>>,
}

pub fn parse_avcc(b: &[u8]) -> Option<AvcC> {
    if b.len() < 7 {
        return None;
    }
    let mut c = AvcC {
        profile: b[1],
        compat: b[2],
        level: b[3],
        nal_len: (b[4] & 3) as usize + 1,
        sps: vec![],
        pps: vec![],
    };
    let mut o = 6;
    for _ in 0..(b[5] & 31) {
        let l = be16(b, o) as usize;
        c.sps.push(b.get(o + 2..o + 2 + l)?.to_vec());
        o += 2 + l;
    }
    let n = *b.get(o)?;
    o += 1;
    for _ in 0..n {
        let l = be16(b, o) as usize;
        c.pps.push(b.get(o + 2..o + 2 + l)?.to_vec());
        o += 2 + l;
    }
    Some(c)
}

/// The AudioSpecificConfig inside an `esds` (tag 5 of the decoder config descriptor).
pub fn parse_esds_asc(b: &[u8]) -> Option<Vec<u8>> {
    let mut o = 4; // version/flags
    fn desc_len(b: &[u8], o: &mut usize) -> Option<usize> {
        let mut len = 0usize;
        for _ in 0..4 {
            let x = *b.get(*o)?;
            *o += 1;
            len = (len << 7) | (x & 0x7f) as usize;
            if x & 0x80 == 0 {
                break;
            }
        }
        Some(len)
    }
    while o < b.len() {
        let tag = b[o];
        o += 1;
        let len = desc_len(b, &mut o)?;
        match tag {
            3 => {
                let flags = *b.get(o + 2)?;
                o += 3;
                if flags & 0x80 != 0 {
                    o += 2;
                }
                if flags & 0x40 != 0 {
                    o += 1 + *b.get(o)? as usize;
                }
                if flags & 0x20 != 0 {
                    o += 2;
                }
            }
            4 => o += 13,
            5 => return b.get(o..o + len).map(|s| s.to_vec()),
            _ => o += len,
        }
    }
    None
}

pub fn describe_asc(asc: &[u8]) -> String {
    if asc.len() < 2 {
        return "short".into();
    }
    let aot = asc[0] >> 3;
    let fi = ((asc[0] & 7) << 1) | (asc[1] >> 7);
    let ch = (asc[1] >> 3) & 15;
    const RATES: [u32; 13] = [
        96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350,
    ];
    format!(
        "aot={aot}{} rate={} channel_config={ch}",
        if aot == 2 { "(AAC-LC)" } else { "" },
        RATES
            .get(fi as usize)
            .map(|r| r.to_string())
            .unwrap_or(format!("index{fi}"))
    )
}

struct Bits<'a> {
    b: &'a [u8],
    pos: usize,
}
impl<'a> Bits<'a> {
    fn u(&mut self, n: usize) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            let byte = *self.b.get(self.pos / 8)?;
            v = (v << 1) | ((byte >> (7 - self.pos % 8)) & 1) as u32;
            self.pos += 1;
        }
        Some(v)
    }
    fn ue(&mut self) -> Option<u32> {
        let mut zeros = 0;
        while self.u(1)? == 0 {
            zeros += 1;
            if zeros > 31 {
                return None;
            }
        }
        Some((1u32 << zeros) - 1 + self.u(zeros)?)
    }
    fn se(&mut self) -> Option<i32> {
        let k = self.ue()?;
        Some(if k % 2 == 1 {
            (k as i32 + 1) / 2
        } else {
            -(k as i32 / 2)
        })
    }
}

/// Removes emulation-prevention bytes (`00 00 03` → `00 00`).
pub fn rbsp(nal: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nal.len());
    let mut zeros = 0;
    for &b in nal {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        out.push(b);
        zeros = if b == 0 { zeros + 1 } else { 0 };
    }
    out
}

/// SPS fields up to the VUI's timing info (profile, level, size, VUI colour description, timing).
pub fn describe_sps(sps: &[u8]) -> String {
    let r = rbsp(&sps[1..]);
    let mut b = Bits { b: &r, pos: 0 };
    let mut d = String::new();
    let f = |b: &mut Bits, d: &mut String| -> Option<()> {
        let profile = b.u(8)?;
        let constraints = b.u(8)?;
        let level = b.u(8)?;
        let _id = b.ue()?;
        d.push_str(&format!(
            "profile_idc={profile} constraints={constraints:#04x} level_idc={level}"
        ));
        if [100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135].contains(&profile) {
            let chroma = b.ue()?;
            if chroma == 3 {
                b.u(1)?;
            }
            let bd_luma = b.ue()?;
            let bd_chroma = b.ue()?;
            b.u(1)?;
            let scaling = b.u(1)?;
            d.push_str(&format!(
                " chroma_format={chroma} bit_depth={}/{}",
                bd_luma + 8,
                bd_chroma + 8
            ));
            if scaling == 1 {
                d.push_str(" scaling_matrix=present(unparsed)");
                return Some(());
            }
        }
        let _log2_max_frame_num = b.ue()?;
        let poc_type = b.ue()?;
        if poc_type == 0 {
            b.ue()?;
        } else if poc_type == 1 {
            b.u(1)?;
            b.se()?;
            b.se()?;
            let n = b.ue()?;
            for _ in 0..n {
                b.se()?;
            }
        }
        let refs = b.ue()?;
        b.u(1)?;
        let w_mbs = b.ue()? + 1;
        let h_units = b.ue()? + 1;
        let frame_mbs_only = b.u(1)?;
        if frame_mbs_only == 0 {
            b.u(1)?;
        }
        b.u(1)?;
        let crop = b.u(1)?;
        let (mut cl, mut cr, mut ct, mut cb) = (0, 0, 0, 0);
        if crop == 1 {
            cl = b.ue()?;
            cr = b.ue()?;
            ct = b.ue()?;
            cb = b.ue()?;
        }
        d.push_str(&format!(
            " poc_type={poc_type} max_refs={refs} mbs={w_mbs}x{h_units} frame_mbs_only={frame_mbs_only} crop=[{cl},{cr},{ct},{cb}]"
        ));
        let vui = b.u(1)?;
        d.push_str(&format!(" vui={vui}"));
        if vui == 1 {
            if b.u(1)? == 1 {
                let idc = b.u(8)?;
                d.push_str(&format!(" sar_idc={idc}"));
                if idc == 255 {
                    d.push_str(&format!(" sar={}:{}", b.u(16)?, b.u(16)?));
                }
            }
            if b.u(1)? == 1 {
                b.u(1)?;
            }
            if b.u(1)? == 1 {
                let fmt = b.u(3)?;
                let full = b.u(1)?;
                d.push_str(&format!(" video_format={fmt} full_range={full}"));
                if b.u(1)? == 1 {
                    d.push_str(&format!(" colour=({},{},{})", b.u(8)?, b.u(8)?, b.u(8)?));
                }
            }
            if b.u(1)? == 1 {
                b.ue()?;
                b.ue()?;
            }
            if b.u(1)? == 1 {
                let nu = b.u(32)?;
                let ts = b.u(32)?;
                let fixed = b.u(1)?;
                d.push_str(&format!(" timing={nu}/{ts} fixed={fixed}"));
            }
        }
        Some(())
    };
    if f(&mut b, &mut d).is_none() {
        d.push_str(" (truncated)");
    }
    d
}

/// SEI payload types of one SEI NAL (with the first bytes of user data unregistered).
pub fn sei_payloads(nal: &[u8]) -> Vec<(u32, usize, String)> {
    let r = rbsp(&nal[1..]);
    let mut o = 0;
    let mut out = Vec::new();
    while o < r.len() {
        if r.len() - o == 1 && r[o] == 0x80 {
            break;
        }
        let mut t = 0u32;
        while o < r.len() && r[o] == 0xFF {
            t += 255;
            o += 1;
        }
        if o >= r.len() {
            break;
        }
        t += r[o] as u32;
        o += 1;
        let mut s = 0usize;
        while o < r.len() && r[o] == 0xFF {
            s += 255;
            o += 1;
        }
        if o >= r.len() {
            break;
        }
        s += r[o] as usize;
        o += 1;
        let payload = &r[o..(o + s).min(r.len())];
        let note = if t == 5 && payload.len() >= 16 {
            let text: String = payload[16..]
                .iter()
                .take(80)
                .map(|&c| {
                    if (0x20..0x7f).contains(&c) {
                        c as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("uuid={} text=\"{text}\"", crate::hex(&payload[..16]))
        } else {
            String::new()
        };
        out.push((t, s, note));
        o += s;
    }
    out
}

/// One sample located in the file.
#[derive(Clone, Debug)]
pub struct Sample {
    pub track: u32,
    pub offset: usize,
    pub size: usize,
    pub dts: u64,
    pub duration: u32,
    pub sync: bool,
    /// Index of the `moof` this sample belongs to (fragmented files), else `usize::MAX`.
    pub fragment: usize,
}

/// Track facts from `moov`.
#[derive(Clone, Debug)]
pub struct TrackInfo {
    pub id: u32,
    pub handler: String,
    pub timescale: u32,
    pub entry: String,
    pub avcc: Option<AvcC>,
    pub asc: Option<Vec<u8>>,
    pub width: u16,
    pub height: u16,
    pub rotation: i32,
    pub channels: u16,
    pub samplerate: u32,
}

pub fn tracks(data: &[u8], top: &[BoxNode]) -> Vec<TrackInfo> {
    let mut out = Vec::new();
    let Some(moov) = top.iter().find(|b| &b.typ == b"moov") else {
        return out;
    };
    for trak in moov.find_all(b"trak") {
        let Some(tkhd) = trak.find(b"tkhd") else {
            continue;
        };
        let tb = tkhd.body(data);
        let (id, rest) = if tb[0] == 1 {
            (be32(tb, 20), 36)
        } else {
            (be32(tb, 12), 24)
        };
        let matrix: Vec<i32> = (0..9).map(|i| be32(tb, rest + 16 + 4 * i) as i32).collect();
        let mdhd = trak.path(&[b"mdia", b"mdhd"]).map(|m| m.body(data));
        let timescale = mdhd
            .map(|b| if b[0] == 1 { be32(b, 20) } else { be32(b, 12) })
            .unwrap_or(0);
        let handler = trak
            .path(&[b"mdia", b"hdlr"])
            .map(|h| String::from_utf8_lossy(&h.body(data)[8..12]).to_string())
            .unwrap_or_default();
        let stsd = trak.path(&[b"mdia", b"minf", b"stbl", b"stsd"]);
        let entry = stsd.and_then(|s| s.children.first());
        let mut t = TrackInfo {
            id,
            handler,
            timescale,
            entry: entry.map(|e| e.type_str()).unwrap_or_default(),
            avcc: None,
            asc: None,
            width: 0,
            height: 0,
            rotation: rotation_of(&matrix),
            channels: 0,
            samplerate: 0,
        };
        if let Some(e) = entry {
            let eb = e.body(data);
            if t.handler == "vide" && eb.len() >= 28 {
                t.width = be16(eb, 24);
                t.height = be16(eb, 26);
            }
            if t.handler == "soun" && eb.len() >= 28 {
                t.channels = be16(eb, 16);
                t.samplerate = be32(eb, 24) >> 16;
            }
            if let Some(a) = e.find(b"avcC") {
                t.avcc = parse_avcc(a.body(data));
            }
            if let Some(es) = e.find(b"esds") {
                t.asc = parse_esds_asc(es.body(data));
            }
        }
        out.push(t);
    }
    out
}

/// Every sample of every track, for fragmented (moof/trun) and plain (stbl) files.
pub fn samples(data: &[u8], top: &[BoxNode]) -> Vec<Sample> {
    let mut out = Vec::new();
    // Fragmented.
    let mut frag_idx = 0;
    let mut trex_defaults: BTreeMap<u32, (u32, u32, u32)> = BTreeMap::new();
    if let Some(mvex) = top
        .iter()
        .find(|b| &b.typ == b"moov")
        .and_then(|m| m.find(b"mvex"))
    {
        for trex in mvex.find_all(b"trex") {
            let b = trex.body(data);
            trex_defaults.insert(be32(b, 4), (be32(b, 12), be32(b, 16), be32(b, 20)));
        }
    }
    for moof in top.iter().filter(|b| &b.typ == b"moof") {
        for traf in moof.find_all(b"traf") {
            let Some(tfhd) = traf.find(b"tfhd") else {
                continue;
            };
            let hb = tfhd.body(data);
            let flags = be32(hb, 0) & 0xFFFFFF;
            let track = be32(hb, 4);
            let (mut ddur, mut dsize, mut dflags) =
                trex_defaults.get(&track).copied().unwrap_or((0, 0, 0));
            let mut o = 8;
            let mut base = moof.offset as u64;
            if flags & 0x1 != 0 {
                base = be64(hb, o);
                o += 8;
            }
            if flags & 0x2 != 0 {
                o += 4;
            }
            if flags & 0x8 != 0 {
                ddur = be32(hb, o);
                o += 4;
            }
            if flags & 0x10 != 0 {
                dsize = be32(hb, o);
                o += 4;
            }
            if flags & 0x20 != 0 {
                dflags = be32(hb, o);
            }
            let mut dts = traf
                .find(b"tfdt")
                .map(|t| {
                    let b = t.body(data);
                    if b[0] == 1 {
                        be64(b, 4)
                    } else {
                        be32(b, 4) as u64
                    }
                })
                .unwrap_or(0);
            for trun in traf.find_all(b"trun") {
                let t = parse_trun(trun.body(data));
                let mut pos = (base as i64 + t.data_offset.unwrap_or(0) as i64) as usize;
                for (i, s) in t.samples.iter().enumerate() {
                    let size = s.size.unwrap_or(dsize) as usize;
                    let dur = s.duration.unwrap_or(ddur);
                    let fl = if i == 0 {
                        t.first_sample_flags.or(s.flags).unwrap_or(dflags)
                    } else {
                        s.flags.unwrap_or(dflags)
                    };
                    out.push(Sample {
                        track,
                        offset: pos,
                        size,
                        dts,
                        duration: dur,
                        sync: is_sync(fl),
                        fragment: frag_idx,
                    });
                    pos += size;
                    dts += dur as u64;
                }
            }
        }
        frag_idx += 1;
    }
    if !out.is_empty() {
        return out;
    }
    // Plain: stts, stsz, stsc, stco/co64, stss.
    let Some(moov) = top.iter().find(|b| &b.typ == b"moov") else {
        return out;
    };
    for (ti, trak) in moov.find_all(b"trak").into_iter().enumerate() {
        let tinfo = tracks(data, top);
        let track = tinfo.get(ti).map(|t| t.id).unwrap_or(ti as u32 + 1);
        let Some(stbl) = trak.path(&[b"mdia", b"minf", b"stbl"]) else {
            continue;
        };
        let sizes: Vec<u32> = match stbl.find(b"stsz") {
            Some(s) => {
                let b = s.body(data);
                let fixed = be32(b, 4);
                let n = be32(b, 8) as usize;
                if fixed != 0 {
                    vec![fixed; n]
                } else {
                    (0..n).map(|i| be32(b, 12 + 4 * i)).collect()
                }
            }
            None => continue,
        };
        let chunks: Vec<u64> = if let Some(s) = stbl.find(b"stco") {
            let b = s.body(data);
            (0..be32(b, 4) as usize)
                .map(|i| be32(b, 8 + 4 * i) as u64)
                .collect()
        } else if let Some(s) = stbl.find(b"co64") {
            let b = s.body(data);
            (0..be32(b, 4) as usize)
                .map(|i| be64(b, 8 + 8 * i))
                .collect()
        } else {
            continue;
        };
        let stsc: Vec<(u32, u32)> = stbl
            .find(b"stsc")
            .map(|s| {
                let b = s.body(data);
                (0..be32(b, 4) as usize)
                    .map(|i| (be32(b, 8 + 12 * i), be32(b, 12 + 12 * i)))
                    .collect()
            })
            .unwrap_or_default();
        let mut durs = Vec::new();
        if let Some(s) = stbl.find(b"stts") {
            let b = s.body(data);
            for i in 0..be32(b, 4) as usize {
                let (c, d) = (be32(b, 8 + 8 * i), be32(b, 12 + 8 * i));
                for _ in 0..c {
                    durs.push(d);
                }
            }
        }
        let sync: Option<Vec<u32>> = stbl.find(b"stss").map(|s| {
            let b = s.body(data);
            (0..be32(b, 4) as usize)
                .map(|i| be32(b, 8 + 4 * i))
                .collect()
        });
        let mut si = 0usize;
        let mut dts = 0u64;
        for (ci, &coff) in chunks.iter().enumerate() {
            let chunk_no = ci as u32 + 1;
            let per = stsc
                .iter()
                .rev()
                .find(|(first, _)| *first <= chunk_no)
                .map(|x| x.1)
                .unwrap_or(1);
            let mut pos = coff as usize;
            for _ in 0..per {
                if si >= sizes.len() {
                    break;
                }
                let d = durs.get(si).copied().unwrap_or(0);
                let is_sync = sync
                    .as_ref()
                    .map(|v| v.contains(&(si as u32 + 1)))
                    .unwrap_or(true);
                out.push(Sample {
                    track,
                    offset: pos,
                    size: sizes[si] as usize,
                    dts,
                    duration: d,
                    sync: is_sync,
                    fragment: usize::MAX,
                });
                pos += sizes[si] as usize;
                dts += d as u64;
                si += 1;
            }
        }
    }
    out
}

/// Splits a length-prefixed AVC sample into NAL units.
pub fn nal_units(sample: &[u8], nal_len: usize) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut o = 0;
    while o + nal_len <= sample.len() {
        let mut l = 0usize;
        for i in 0..nal_len {
            l = (l << 8) | sample[o + i] as usize;
        }
        o += nal_len;
        if o + l > sample.len() {
            break;
        }
        out.push(&sample[o..o + l]);
        o += l;
    }
    out
}

/// Builds GHOST's `mfra` of design §8.3: one `tfra` (version 1) for `track` with one entry per
/// `moof` (time = that track's `tfdt`, offset = the `moof`'s file offset, traf/trun/sample 1), then
/// `mfro`.
pub fn build_mfra(data: &[u8], top: &[BoxNode], track: u32) -> Vec<u8> {
    let mut entries = Vec::new();
    for moof in top.iter().filter(|b| &b.typ == b"moof") {
        for (ti, traf) in moof.find_all(b"traf").into_iter().enumerate() {
            let hb = traf.find(b"tfhd").map(|t| t.body(data)).unwrap_or(&[]);
            if hb.len() >= 8 && be32(hb, 4) == track {
                let t = traf.find(b"tfdt").map(|t| {
                    let b = t.body(data);
                    if b[0] == 1 {
                        be64(b, 4)
                    } else {
                        be32(b, 4) as u64
                    }
                });
                if let Some(time) = t {
                    entries.push((time, moof.offset as u64, ti as u8 + 1));
                }
            }
        }
    }
    let mut tfra = Vec::new();
    tfra.extend_from_slice(&[1, 0, 0, 0]);
    tfra.extend_from_slice(&track.to_be_bytes());
    tfra.extend_from_slice(&0u32.to_be_bytes()); // 1-byte traf, trun and sample numbers
    tfra.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (time, off, traf_no) in &entries {
        tfra.extend_from_slice(&time.to_be_bytes());
        tfra.extend_from_slice(&off.to_be_bytes());
        tfra.extend_from_slice(&[*traf_no, 1, 1]);
    }
    let tfra_box = boxed(b"tfra", &tfra);
    let mfra_size = 8 + tfra_box.len() + 16;
    let mfro = boxed(
        b"mfro",
        &[&[0u8, 0, 0, 0][..], &(mfra_size as u32).to_be_bytes()].concat(),
    );
    boxed(b"mfra", &[tfra_box, mfro].concat())
}

pub fn boxed(t: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut b = ((body.len() + 8) as u32).to_be_bytes().to_vec();
    b.extend_from_slice(t);
    b.extend_from_slice(body);
    b
}
