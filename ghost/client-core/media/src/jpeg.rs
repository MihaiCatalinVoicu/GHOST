//! The canonical JPEG profile and `jpegCanonicalize` (design §8.2, §13.2 M9).
//!
//! | Allowed | Refused |
//! |---|---|
//! | `SOI`; `DQT` (8-bit, 1–4 tables); `SOF0` only (baseline, 8-bit, 1 or 3 components); `DHT`; `DRI`; `SOS`; entropy-coded data with `RST0`–`RST7`; `EOI` | every `APP0`–`APP15`, `COM`, `SOF1`–`SOF15`, `DNL`, `DAC`, `DHP`, `EXP`, reserved markers, any byte after `EOI`, a missing `EOI`, a second `SOI` |
//!
//! [`JpegWalker`] is one streaming pass with bounded memory (one segment, at most 65 533 bytes):
//! the sealer and the reader feed it chunk by chunk. In `Check` mode an `APPn` or `COM` segment is
//! refused (a canonical file has none, so `canonicalize(x) = x` exactly when `check(x)` passes);
//! in `Strip` mode, which [`canonicalize`] uses, those segments are dropped and every other byte is
//! kept as it is. The walker is stricter than the table in three places the profile implies:
//! no fill bytes (`0xFF 0xFF`) anywhere, restart markers only with a non-zero `DRI` and in their
//! cyclic order, and the baseline table limits (Huffman tables and scan selectors 0 or 1).
//! What it reports is the `SOF0` geometry; the D29 checks are the caller's.

use zeroize::Zeroizing;

use crate::error::{MediaError, MediaResult};

const SOI: u8 = 0xD8;
const EOI: u8 = 0xD9;
const SOF0: u8 = 0xC0;
const DHT: u8 = 0xC4;
const DQT: u8 = 0xDB;
const DRI: u8 = 0xDD;
const SOS: u8 = 0xDA;
const COM: u8 = 0xFE;

/// What the walker parsed from `SOF0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JpegInfo {
    /// `X`, the width.
    pub width: u16,
    /// `Y`, the height.
    pub height: u16,
    /// `Nf`, 1 or 3.
    pub components: u8,
}

/// Whether `APPn` and `COM` are refused (`Check`) or dropped (`Strip`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JpegMode {
    Check,
    Strip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum St {
    Soi0,
    Soi1,
    MarkerFf,
    MarkerCode,
    Len0,
    Len1(u8),
    Payload { left: u16, keep: bool, parse: bool },
    Entropy,
    EntropyFf,
    End,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Sof {
    width: u16,
    height: u16,
    ids: Vec<u8>,
}

/// The streaming walker of the canonical JPEG profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct JpegWalker {
    mode: JpegMode,
    st: St,
    marker: u8,
    seg: Zeroizing<Vec<u8>>,
    sof: Option<Sof>,
    scans: u32,
    restart_interval: u16,
    next_rst: u8,
    /// The first refusal: every later call repeats it.
    failed: Option<MediaError>,
}

fn nc(rule: &'static str) -> MediaError {
    MediaError::non_canonical(rule)
}

fn is_app(m: u8) -> bool {
    (0xE0..=0xEF).contains(&m)
}

fn is_rst(m: u8) -> bool {
    (0xD0..=0xD7).contains(&m)
}

impl JpegWalker {
    pub(crate) fn new(mode: JpegMode) -> Self {
        JpegWalker {
            mode,
            st: St::Soi0,
            marker: 0,
            seg: Zeroizing::new(Vec::new()),
            sof: None,
            scans: 0,
            restart_interval: 0,
            next_rst: 0,
            failed: None,
        }
    }

    fn emit(out: &mut Option<&mut Vec<u8>>, bytes: &[u8]) {
        if let Some(o) = out.as_deref_mut() {
            o.extend_from_slice(bytes);
        }
    }

    /// Feeds the next bytes of the file. In `Strip` mode the kept bytes are appended to `out`.
    pub(crate) fn feed(&mut self, data: &[u8], out: Option<&mut Vec<u8>>) -> MediaResult<()> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let result = self.feed_inner(data, out);
        if let Err(e) = result {
            self.failed = Some(e);
        }
        result
    }

    fn feed_inner(&mut self, data: &[u8], mut out: Option<&mut Vec<u8>>) -> MediaResult<()> {
        let mut i = 0usize;
        while let Some(rest) = data.get(i..) {
            let Some(&b) = rest.first() else { break };
            match self.st {
                St::Soi0 => {
                    if b != 0xFF {
                        return Err(nc("a JPEG starts with SOI"));
                    }
                    self.st = St::Soi1;
                    i = i.saturating_add(1);
                }
                St::Soi1 => {
                    if b != SOI {
                        return Err(nc("a JPEG starts with SOI"));
                    }
                    Self::emit(&mut out, &[0xFF, SOI]);
                    self.st = St::MarkerFf;
                    i = i.saturating_add(1);
                }
                St::MarkerFf => {
                    if b != 0xFF {
                        return Err(nc("bytes between JPEG segments"));
                    }
                    self.st = St::MarkerCode;
                    i = i.saturating_add(1);
                }
                St::MarkerCode => {
                    i = i.saturating_add(1);
                    self.marker_code(b, &mut out)?;
                }
                St::Len0 => {
                    self.st = St::Len1(b);
                    i = i.saturating_add(1);
                }
                St::Len1(hi) => {
                    i = i.saturating_add(1);
                    let len = u16::from_be_bytes([hi, b]);
                    if len < 2 {
                        return Err(nc("a JPEG segment length below 2"));
                    }
                    let keep = !self.dropped(self.marker);
                    if keep {
                        Self::emit(&mut out, &[0xFF, self.marker, hi, b]);
                    }
                    let left = len.saturating_sub(2);
                    let parse = keep;
                    self.seg.clear();
                    self.st = St::Payload { left, keep, parse };
                    if left == 0 {
                        self.end_segment()?;
                    }
                }
                St::Payload { left, keep, parse } => {
                    let n = usize::from(left).min(rest.len());
                    let chunk = rest.get(..n).unwrap_or(&[]);
                    if keep {
                        Self::emit(&mut out, chunk);
                    }
                    if parse {
                        self.seg.extend_from_slice(chunk);
                    }
                    i = i.saturating_add(n);
                    let left = left.saturating_sub(u16::try_from(n).unwrap_or(u16::MAX));
                    self.st = St::Payload { left, keep, parse };
                    if left == 0 {
                        self.end_segment()?;
                    }
                }
                St::Entropy => {
                    let run = rest.iter().position(|x| *x == 0xFF).unwrap_or(rest.len());
                    Self::emit(&mut out, rest.get(..run).unwrap_or(&[]));
                    i = i.saturating_add(run);
                    if run < rest.len() {
                        self.st = St::EntropyFf;
                        i = i.saturating_add(1);
                    }
                }
                St::EntropyFf => {
                    i = i.saturating_add(1);
                    if b == 0x00 {
                        Self::emit(&mut out, &[0xFF, 0x00]);
                        self.st = St::Entropy;
                    } else if is_rst(b) {
                        if self.restart_interval == 0 {
                            return Err(nc("a restart marker without DRI"));
                        }
                        if b != 0xD0u8.saturating_add(self.next_rst) {
                            return Err(nc("restart markers out of their cyclic order"));
                        }
                        self.next_rst = self.next_rst.saturating_add(1) % 8;
                        Self::emit(&mut out, &[0xFF, b]);
                        self.st = St::Entropy;
                    } else if b == 0xFF {
                        return Err(nc("a fill byte in a JPEG"));
                    } else {
                        // A marker ends the scan.
                        self.marker_code(b, &mut out)?;
                    }
                }
                St::End => return Err(nc("a byte after EOI")),
            }
        }
        Ok(())
    }

    fn dropped(&self, m: u8) -> bool {
        self.mode == JpegMode::Strip && (is_app(m) || m == COM)
    }

    fn marker_code(&mut self, m: u8, out: &mut Option<&mut Vec<u8>>) -> MediaResult<()> {
        match m {
            EOI => {
                if self.scans == 0 {
                    return Err(nc("EOI before any scan"));
                }
                Self::emit(out, &[0xFF, EOI]);
                self.st = St::End;
                Ok(())
            }
            SOI => Err(nc("a second SOI")),
            0xFF => Err(nc("a fill byte in a JPEG")),
            SOF0 | DHT | DQT | DRI | SOS => {
                self.marker = m;
                self.st = St::Len0;
                Ok(())
            }
            _ if is_app(m) || m == COM => {
                if self.mode == JpegMode::Check {
                    return Err(nc("an APPn or COM segment in a canonical JPEG"));
                }
                self.marker = m;
                self.st = St::Len0;
                Ok(())
            }
            _ if is_rst(m) => Err(nc("a restart marker outside entropy-coded data")),
            _ => Err(nc(
                "a JPEG marker outside the profile (SOF1-15, DNL, DAC, DHP, EXP or reserved)",
            )),
        }
    }

    fn end_segment(&mut self) -> MediaResult<()> {
        let m = self.marker;
        let seg = core::mem::take(&mut *self.seg);
        let seg = Zeroizing::new(seg);
        let result = match m {
            DQT => self.dqt(&seg),
            SOF0 => self.sof0(&seg),
            DHT => dht(&seg),
            DRI => self.dri(&seg),
            SOS => self.sos(&seg),
            _ => Ok(()), // APPn / COM, dropped in Strip mode
        };
        result?;
        self.st = if m == SOS { St::Entropy } else { St::MarkerFf };
        if m == SOS {
            self.next_rst = 0;
        }
        Ok(())
    }

    fn dqt(&mut self, seg: &[u8]) -> MediaResult<()> {
        if seg.is_empty() || !seg.len().is_multiple_of(65) || seg.len() / 65 > 4 {
            return Err(nc("a DQT holds 1 to 4 8-bit tables"));
        }
        for table in seg.chunks(65) {
            let pq_tq = table.first().copied().unwrap_or(0xFF);
            if pq_tq >> 4 != 0 || pq_tq & 0x0F > 3 {
                return Err(nc("a DQT table is 8-bit with Tq 0 to 3"));
            }
        }
        Ok(())
    }

    fn sof0(&mut self, seg: &[u8]) -> MediaResult<()> {
        if self.sof.is_some() {
            return Err(nc("a second SOF0"));
        }
        let mut c = crate::bytes::Cursor::new(seg, "a malformed SOF0");
        let precision = c.u8()?;
        let height = c.u16()?;
        let width = c.u16()?;
        let nf = c.u8()?;
        if precision != 8 || height == 0 || width == 0 || !(nf == 1 || nf == 3) {
            return Err(nc("SOF0 is 8-bit, non-empty, with 1 or 3 components"));
        }
        let mut ids = Vec::with_capacity(3);
        for _ in 0..nf {
            let id = c.u8()?;
            let hv = c.u8()?;
            let tq = c.u8()?;
            let (h, v) = (hv >> 4, hv & 0x0F);
            if ids.contains(&id) || !(1..=4).contains(&h) || !(1..=4).contains(&v) || tq > 3 {
                return Err(nc(
                    "a SOF0 component is distinct, sampled 1 to 4, with Tq 0 to 3",
                ));
            }
            ids.push(id);
        }
        c.finish()?;
        self.sof = Some(Sof { width, height, ids });
        Ok(())
    }

    fn dri(&mut self, seg: &[u8]) -> MediaResult<()> {
        let mut c = crate::bytes::Cursor::new(seg, "a DRI is two bytes");
        self.restart_interval = c.u16()?;
        c.finish()
    }

    fn sos(&mut self, seg: &[u8]) -> MediaResult<()> {
        let Some(sof) = self.sof.as_ref() else {
            return Err(nc("SOS before SOF0"));
        };
        let mut c = crate::bytes::Cursor::new(seg, "a malformed SOS");
        let ns = c.u8()?;
        if ns == 0 || usize::from(ns) > sof.ids.len() {
            return Err(nc("an SOS names 1 to Nf components"));
        }
        let mut seen: Vec<u8> = Vec::with_capacity(3);
        for _ in 0..ns {
            let cs = c.u8()?;
            let td_ta = c.u8()?;
            if !sof.ids.contains(&cs) || seen.contains(&cs) || td_ta >> 4 > 1 || td_ta & 0x0F > 1 {
                return Err(nc(
                    "an SOS component is a distinct SOF0 component with baseline tables",
                ));
            }
            seen.push(cs);
        }
        let (ss, se, a) = (c.u8()?, c.u8()?, c.u8()?);
        if ss != 0 || se != 63 || a != 0 {
            return Err(nc("a baseline scan has Ss 0, Se 63, Ah = Al = 0"));
        }
        c.finish()?;
        self.scans = self.scans.saturating_add(1);
        Ok(())
    }

    /// The parsed geometry, once the file ended exactly at `EOI`.
    pub(crate) fn finish(&self) -> MediaResult<JpegInfo> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if self.st != St::End {
            return Err(nc("a JPEG without EOI"));
        }
        let sof = self.sof.as_ref().ok_or_else(|| nc("a JPEG without SOF0"))?;
        Ok(JpegInfo {
            width: sof.width,
            height: sof.height,
            components: u8::try_from(sof.ids.len()).unwrap_or(0),
        })
    }
}

fn dht(seg: &[u8]) -> MediaResult<()> {
    let mut c = crate::bytes::Cursor::new(seg, "a malformed DHT");
    if c.is_empty() {
        return Err(nc("an empty DHT"));
    }
    while !c.is_empty() {
        let tc_th = c.u8()?;
        if tc_th >> 4 > 1 || tc_th & 0x0F > 1 {
            return Err(nc("a baseline DHT table is class 0 or 1, number 0 or 1"));
        }
        let counts = c.take(16)?;
        let total: usize = counts.iter().map(|x| usize::from(*x)).sum();
        if total == 0 || total > 256 {
            return Err(nc("a DHT table holds 1 to 256 codes"));
        }
        c.take(total)?;
    }
    Ok(())
}

/// The streaming form of [`check`]: the file in pieces of any size gives the result one piece
/// gives (a refusal ends the walk; feeding after it repeats it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JpegChecker(JpegWalker);

impl Default for JpegChecker {
    fn default() -> Self {
        JpegChecker(JpegWalker::new(JpegMode::Check))
    }
}

impl JpegChecker {
    /// A checker at the start of a file.
    pub fn new() -> Self {
        Self::default()
    }

    /// Walks the next bytes.
    pub fn feed(&mut self, data: &[u8]) -> MediaResult<()> {
        self.0.feed(data, None)
    }

    /// The `SOF0` geometry, once the file ended exactly at `EOI`.
    pub fn finish(&self) -> MediaResult<JpegInfo> {
        self.0.finish()
    }
}

/// Checks that `bytes` is exactly one canonical JPEG and returns its `SOF0` geometry.
pub fn check(bytes: &[u8]) -> MediaResult<JpegInfo> {
    let mut w = JpegWalker::new(JpegMode::Check);
    w.feed(bytes, None)?;
    w.finish()
}

/// `jpegCanonicalize` (§8.2, §13.2 M9): drops every `APP0`–`APP15` and `COM` segment, keeps every
/// allowed segment byte for byte, and refuses anything in the refused column. The output passes
/// [`check`], and `canonicalize(canonicalize(x)) = canonicalize(x)`.
pub fn canonicalize(bytes: &[u8]) -> MediaResult<Vec<u8>> {
    let mut w = JpegWalker::new(JpegMode::Strip);
    let mut out = Vec::with_capacity(bytes.len());
    w.feed(bytes, Some(&mut out))?;
    w.finish()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal canonical grayscale JPEG of `w × h` (not a decodable picture: one DHT table).
    fn tiny(w: u16, h: u16) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8];
        v.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
        v.extend_from_slice(&[1u8; 64]);
        v.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x0B, 0x08]);
        v.extend_from_slice(&h.to_be_bytes());
        v.extend_from_slice(&w.to_be_bytes());
        v.extend_from_slice(&[0x01, 0x01, 0x11, 0x00]);
        v.extend_from_slice(&[0xFF, 0xC4, 0x00, 0x14, 0x00]);
        v.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        v.push(0x00);
        v.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
        v.extend_from_slice(&[0x12, 0xFF, 0x00, 0x34]);
        v.extend_from_slice(&[0xFF, 0xD9]);
        v
    }

    #[test]
    fn accepts_the_profile_and_reports_sof0() {
        let j = tiny(320, 208);
        assert_eq!(
            check(&j).expect("canonical"),
            JpegInfo {
                width: 320,
                height: 208,
                components: 1
            }
        );
        assert_eq!(canonicalize(&j).expect("fixed point"), j);
    }

    #[test]
    fn strips_app_and_com_and_refuses_them_in_check_mode() {
        let j = tiny(512, 336);
        let mut with = j[..2].to_vec();
        with.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x06, b'E', b'x', b'i', b'f']);
        with.extend_from_slice(&[0xFF, 0xE2, 0x00, 0x04, 0x01, 0x02]);
        with.extend_from_slice(&[0xFF, 0xED, 0x00, 0x03, 0x09]);
        with.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x02]);
        with.extend_from_slice(&j[2..]);
        assert_eq!(canonicalize(&with).expect("stripped"), j);
        assert!(check(&with).is_err());
    }

    #[test]
    fn refuses_what_the_profile_refuses() {
        let j = tiny(512, 512);
        let mut trailer = j.clone();
        trailer.push(0x00);
        assert!(check(&trailer).is_err());
        assert!(canonicalize(&trailer).is_err());
        assert!(check(&j[..j.len() - 1]).is_err());
        let mut second_soi = j.clone();
        second_soi.splice(2..2, [0xFF, 0xD8]);
        assert!(check(&second_soi).is_err());
        let mut progressive = j.clone();
        let at = progressive
            .windows(2)
            .position(|w| w == [0xFF, 0xC0])
            .expect("SOF0");
        progressive[at + 1] = 0xC2;
        assert!(check(&progressive).is_err());
        let mut fill = j.clone();
        fill.splice(2..2, [0xFF]);
        assert!(check(&fill).is_err());
    }
}
