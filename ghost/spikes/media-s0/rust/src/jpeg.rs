//! JPEG marker walker and the canonicaliser of design §8.2 (`jpegCanonicalize`), used on what
//! `Bitmap.compress` wrote on the emulators (V-M6) and on the image sources (V-M4, V-M5).

/// One marker segment (or the entropy-coded data after a SOS).
#[derive(Clone, Debug)]
pub struct Segment {
    pub offset: usize,
    pub marker: u8,
    /// Length of the whole segment including the marker (2 for SOI/EOI/RSTn).
    pub len: usize,
    pub detail: String,
}

/// What the walk found.
#[derive(Clone, Debug, Default)]
pub struct Walk {
    pub segments: Vec<Segment>,
    /// Bytes after EOI.
    pub trailing: usize,
    /// Bytes of 0xFF fill before a marker.
    pub fill_bytes: usize,
    pub eoi: bool,
    pub width: u16,
    pub height: u16,
    pub sof: Option<u8>,
    pub errors: Vec<String>,
}

fn name(m: u8) -> String {
    match m {
        0xD8 => "SOI".into(),
        0xD9 => "EOI".into(),
        0xDA => "SOS".into(),
        0xDB => "DQT".into(),
        0xC4 => "DHT".into(),
        0xDD => "DRI".into(),
        0xFE => "COM".into(),
        0xCC => "DAC".into(),
        0xDC => "DNL".into(),
        0xDE => "DHP".into(),
        0xDF => "EXP".into(),
        0xC0..=0xCF => format!("SOF{}", m - 0xC0),
        0xE0..=0xEF => format!("APP{}", m - 0xE0),
        0xD0..=0xD7 => format!("RST{}", m - 0xD0),
        _ => format!("0x{m:02X}"),
    }
}

fn printable_id(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len()).min(40);
    b[..end]
        .iter()
        .map(|&c| {
            if (0x20..0x7f).contains(&c) {
                c as char
            } else {
                '.'
            }
        })
        .collect()
}

/// Walks every marker of `data`.
pub fn walk(data: &[u8]) -> Walk {
    let mut w = Walk::default();
    if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
        w.errors.push("no SOI at offset 0".into());
        return w;
    }
    w.segments.push(Segment {
        offset: 0,
        marker: 0xD8,
        len: 2,
        detail: String::new(),
    });
    let mut p = 2;
    loop {
        if p >= data.len() {
            w.errors.push("missing EOI".into());
            return w;
        }
        if data[p] != 0xFF {
            w.errors.push(format!("expected a marker at {p}"));
            return w;
        }
        let mut q = p + 1;
        while q < data.len() && data[q] == 0xFF {
            w.fill_bytes += 1;
            q += 1;
        }
        if q >= data.len() {
            w.errors.push("truncated marker".into());
            return w;
        }
        let m = data[q];
        let off = q - 1;
        match m {
            0xD9 => {
                w.segments.push(Segment {
                    offset: off,
                    marker: m,
                    len: 2,
                    detail: String::new(),
                });
                w.eoi = true;
                w.trailing = data.len() - (q + 1);
                return w;
            }
            0xD8 => {
                w.errors.push(format!("second SOI at {off}"));
                return w;
            }
            0x01 | 0xD0..=0xD7 => {
                w.segments.push(Segment {
                    offset: off,
                    marker: m,
                    len: 2,
                    detail: "standalone".into(),
                });
                p = q + 1;
                continue;
            }
            _ => {}
        }
        if q + 3 > data.len() {
            w.errors.push("truncated length".into());
            return w;
        }
        let len = u16::from_be_bytes([data[q + 1], data[q + 2]]) as usize;
        let body_start = q + 3;
        let body_end = q + 1 + len;
        if len < 2 || body_end > data.len() {
            w.errors.push(format!("bad length {len} at {off}"));
            return w;
        }
        let body = &data[body_start..body_end];
        let mut detail = String::new();
        match m {
            0xE0..=0xEF => {
                detail = format!("id=\"{}\"", printable_id(body));
            }
            0xFE => detail = format!("comment=\"{}\"", printable_id(body)),
            0xDB => {
                let mut i = 0;
                let mut tables = Vec::new();
                while i < body.len() {
                    let pq = body[i] >> 4;
                    let tq = body[i] & 15;
                    tables.push(format!("T{tq}/{}bit", if pq == 0 { 8 } else { 16 }));
                    i += 1 + if pq == 0 { 64 } else { 128 };
                }
                detail = tables.join(",");
            }
            0xC4 => {
                let mut i = 0;
                let mut tables = Vec::new();
                while i + 17 <= body.len() {
                    let tc = body[i] >> 4;
                    let th = body[i] & 15;
                    let n: usize = body[i + 1..i + 17].iter().map(|&x| x as usize).sum();
                    tables.push(format!("{}{th}", if tc == 0 { "DC" } else { "AC" }));
                    i += 17 + n;
                }
                detail = tables.join(",");
            }
            0xC0..=0xCF if m != 0xC4 && m != 0xC8 && m != 0xCC => {
                if body.len() >= 6 {
                    let precision = body[0];
                    let h = u16::from_be_bytes([body[1], body[2]]);
                    let wd = u16::from_be_bytes([body[3], body[4]]);
                    let nf = body[5] as usize;
                    let mut comps = Vec::new();
                    for c in 0..nf {
                        let b = 6 + 3 * c;
                        if b + 3 <= body.len() {
                            comps.push(format!(
                                "c{}:{}x{}q{}",
                                body[b],
                                body[b + 1] >> 4,
                                body[b + 1] & 15,
                                body[b + 2]
                            ));
                        }
                    }
                    detail = format!("{precision}bit {wd}x{h} comps=[{}]", comps.join(" "));
                    if w.sof.is_some() {
                        w.errors.push("second SOF".into());
                    }
                    w.sof = Some(m);
                    w.width = wd;
                    w.height = h;
                }
            }
            0xDD => {
                if body.len() == 2 {
                    detail = format!("Ri={}", u16::from_be_bytes([body[0], body[1]]));
                }
            }
            0xDA if !body.is_empty() => {
                let ns = body[0] as usize;
                let tail = &body[1 + 2 * ns..];
                if tail.len() == 3 {
                    detail = format!(
                        "Ns={ns} Ss={} Se={} Ah={} Al={}",
                        tail[0],
                        tail[1],
                        tail[2] >> 4,
                        tail[2] & 15
                    );
                }
            }
            _ => {}
        }
        w.segments.push(Segment {
            offset: off,
            marker: m,
            len: len + 2,
            detail,
        });
        p = body_end;
        if m == 0xDA {
            // Entropy-coded data: up to the next marker that is not a stuffed 0x00 or an RSTn.
            let start = p;
            let mut rst = 0usize;
            loop {
                if p + 1 >= data.len() {
                    w.errors.push("entropy-coded data runs to the end".into());
                    return w;
                }
                if data[p] == 0xFF {
                    let nx = data[p + 1];
                    if nx == 0x00 {
                        p += 2;
                        continue;
                    }
                    if (0xD0..=0xD7).contains(&nx) {
                        rst += 1;
                        p += 2;
                        continue;
                    }
                    if nx == 0xFF {
                        p += 1;
                        continue;
                    }
                    break;
                }
                p += 1;
            }
            w.segments.push(Segment {
                offset: start,
                marker: 0x00,
                len: p - start,
                detail: format!("entropy-coded data, {rst} RST markers"),
            });
        }
    }
}

/// Prints one line per segment.
pub fn describe(w: &Walk) -> String {
    let mut out = String::new();
    for s in &w.segments {
        let n = if s.marker == 0 {
            "ECS".to_string()
        } else {
            name(s.marker)
        };
        out.push_str(&format!(
            "{:>9} {:<6} len={:<8} {}\n",
            s.offset, n, s.len, s.detail
        ));
    }
    out.push_str(&format!(
        "summary: sof={} {}x{} eoi={} trailing_after_eoi={} fill_bytes={} errors={:?}\n",
        w.sof.map(name).unwrap_or_else(|| "none".into()),
        w.width,
        w.height,
        w.eoi,
        w.trailing,
        w.fill_bytes,
        w.errors
    ));
    out
}

/// `jpegCanonicalize` of design §8.2: drops APP0–APP15 and COM, keeps SOI, DQT (8-bit), SOF0
/// (8-bit, 1 or 3 components), DHT, DRI, SOS with its entropy-coded data and RSTn, EOI, byte for
/// byte; fails on anything in the refused column (other SOFn, DNL, DAC, DHP, EXP, reserved
/// markers, a 16-bit DQT, fill bytes, any byte after EOI, a missing EOI, a second SOI or SOF).
pub fn canonicalize(data: &[u8]) -> Result<Vec<u8>, String> {
    let w = walk(data);
    if !w.errors.is_empty() {
        return Err(format!("walk: {:?}", w.errors));
    }
    if w.trailing != 0 {
        return Err(format!("{} bytes after EOI", w.trailing));
    }
    if w.fill_bytes != 0 {
        return Err(format!("{} fill bytes", w.fill_bytes));
    }
    if w.sof != Some(0xC0) {
        return Err(format!("SOF is {:?}, not SOF0", w.sof.map(name)));
    }
    let mut out = Vec::with_capacity(data.len());
    for s in &w.segments {
        let bytes = &data[s.offset..s.offset + s.len];
        match s.marker {
            0xE0..=0xEF | 0xFE => continue,
            0xD8 | 0xD9 | 0xC4 | 0xDD | 0xDA | 0x00 | 0xD0..=0xD7 => out.extend_from_slice(bytes),
            0xDB => {
                if s.detail.contains("16bit") {
                    return Err("16-bit DQT".into());
                }
                out.extend_from_slice(bytes);
            }
            0xC0 => {
                let precision = bytes[4];
                let nf = bytes[9];
                if precision != 8 || !(nf == 1 || nf == 3) {
                    return Err(format!("SOF0 precision {precision} components {nf}"));
                }
                out.extend_from_slice(bytes);
            }
            m => return Err(format!("refused marker {}", name(m))),
        }
    }
    Ok(out)
}
