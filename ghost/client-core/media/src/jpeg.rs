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
//! kept as it is. The walker is stricter than the table where the baseline process (ITU-T T.81)
//! implies it (S1's reading, design §22.2 row 9):
//!
//! - no fill bytes (`0xFF 0xFF`) anywhere; restart markers only with a non-zero `DRI` and in their
//!   cyclic order;
//! - the baseline table limits: Huffman tables and scan selectors 0 or 1, `Ss` 0, `Se` 63,
//!   `Ah` = `Al` = 0;
//! - **every table at most once** (a quantisation table `Tq`, a Huffman table `(Tc, Th)`, the
//!   `DRI`), **every `SOF0` component coded by exactly one scan** (a sequential file codes each
//!   component once), and every table a scan uses defined before it. So the bytes outside the
//!   entropy-coded data are bounded (4 quantisation and 4 Huffman tables, at most 3 scans, about
//!   1.4 KiB) where repeated table segments were not (the review of S1: 16 000 `DQT` segments,
//!   1.1 MB, walked as canonical).
//!
//! What it reports is the `SOF0` geometry; the D29 checks are the caller's. The bytes the profile
//! leaves free — the entropy-coded data and the table values — are decoder syntax, not metadata
//! fields (the segments metadata lives in, `APPn` and `COM`, are refused; §22.2 row 9).

use zeroize::Zeroizing;

use crate::bytes::{extend_wiped, reserve_wiped};
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
    /// `(Ci, Tqi)` per component.
    components: Vec<(u8, u8)>,
}

/// The streaming walker of the canonical JPEG profile.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct JpegWalker {
    mode: JpegMode,
    st: St,
    marker: u8,
    seg: Zeroizing<Vec<u8>>,
    sof: Option<Sof>,
    scans: u32,
    restart_interval: u16,
    next_rst: u8,
    /// Bit `Tq` set: that quantisation table is defined.
    dqt: u8,
    /// Bit `2 · Tc + Th` set: that Huffman table is defined.
    dht: u8,
    /// Whether the file has had its `DRI`.
    dri: bool,
    /// The `SOF0` components a scan has coded.
    scanned: Vec<u8>,
    /// The first refusal: every later call repeats it.
    failed: Option<MediaError>,
}

impl core::fmt::Debug for JpegWalker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The segment buffer holds the picture's own bytes: it never renders.
        f.debug_struct("JpegWalker")
            .field("mode", &self.mode)
            .field("state", &self.st)
            .field("scans", &self.scans)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
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

/// The bit of Huffman table `(class, number)`, both 0 or 1.
fn dht_bit(class: u8, number: u8) -> u8 {
    1u8 << (class.min(1).saturating_mul(2).saturating_add(number.min(1)))
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
            dqt: 0,
            dht: 0,
            dri: false,
            scanned: Vec::new(),
            failed: None,
        }
    }

    fn emit(out: &mut Option<&mut Zeroizing<Vec<u8>>>, bytes: &[u8]) {
        if let Some(o) = out.as_mut() {
            extend_wiped(o, bytes);
        }
    }

    /// Feeds the next bytes of the file. In `Strip` mode the kept bytes are appended to `out`.
    pub(crate) fn feed(
        &mut self,
        data: &[u8],
        out: Option<&mut Zeroizing<Vec<u8>>>,
    ) -> MediaResult<()> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let result = self.feed_inner(data, out);
        if let Err(e) = result {
            self.failed = Some(e);
        }
        result
    }

    fn feed_inner(
        &mut self,
        data: &[u8],
        mut out: Option<&mut Zeroizing<Vec<u8>>>,
    ) -> MediaResult<()> {
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
                    if parse {
                        // The whole segment's room at once: the buffer never grows while it fills.
                        reserve_wiped(&mut self.seg, usize::from(left));
                    }
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
                        extend_wiped(&mut self.seg, chunk);
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

    fn marker_code(&mut self, m: u8, out: &mut Option<&mut Zeroizing<Vec<u8>>>) -> MediaResult<()> {
        match m {
            EOI => {
                if self.scans == 0 {
                    return Err(nc("EOI before any scan"));
                }
                let all = self
                    .sof
                    .as_ref()
                    .is_some_and(|s| s.components.len() == self.scanned.len());
                if !all {
                    return Err(nc(
                        "a SOF0 component that no scan codes (baseline codes each once)",
                    ));
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
        // Moved out whole and wiped when it drops at the end of this call.
        let seg = core::mem::take(&mut self.seg);
        let result = match m {
            DQT => self.dqt(&seg),
            SOF0 => self.sof0(&seg),
            DHT => self.dht(&seg),
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
            let bit = 1u8 << (pq_tq & 0x03);
            if self.dqt & bit != 0 {
                return Err(nc("a quantisation table defined twice"));
            }
            self.dqt |= bit;
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
        let mut components: Vec<(u8, u8)> = Vec::with_capacity(3);
        for _ in 0..nf {
            let id = c.u8()?;
            let hv = c.u8()?;
            let tq = c.u8()?;
            let (h, v) = (hv >> 4, hv & 0x0F);
            if components.iter().any(|(i, _)| *i == id)
                || !(1..=4).contains(&h)
                || !(1..=4).contains(&v)
                || tq > 3
            {
                return Err(nc(
                    "a SOF0 component is distinct, sampled 1 to 4, with Tq 0 to 3",
                ));
            }
            components.push((id, tq));
        }
        c.finish()?;
        self.sof = Some(Sof {
            width,
            height,
            components,
        });
        Ok(())
    }

    fn dri(&mut self, seg: &[u8]) -> MediaResult<()> {
        let mut c = crate::bytes::Cursor::new(seg, "a DRI is two bytes");
        let interval = c.u16()?;
        c.finish()?;
        if self.dri {
            return Err(nc("a second DRI"));
        }
        self.dri = true;
        self.restart_interval = interval;
        Ok(())
    }

    fn dht(&mut self, seg: &[u8]) -> MediaResult<()> {
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
            let bit = dht_bit(tc_th >> 4, tc_th & 0x0F);
            if self.dht & bit != 0 {
                return Err(nc("a Huffman table defined twice"));
            }
            self.dht |= bit;
        }
        Ok(())
    }

    fn sos(&mut self, seg: &[u8]) -> MediaResult<()> {
        let Some(sof) = self.sof.as_ref() else {
            return Err(nc("SOS before SOF0"));
        };
        let mut c = crate::bytes::Cursor::new(seg, "a malformed SOS");
        let ns = c.u8()?;
        if ns == 0 || usize::from(ns) > sof.components.len() {
            return Err(nc("an SOS names 1 to Nf components"));
        }
        let mut seen: Vec<(u8, u8, u8)> = Vec::with_capacity(3);
        for _ in 0..ns {
            let cs = c.u8()?;
            let td_ta = c.u8()?;
            let known = sof.components.iter().find(|(i, _)| *i == cs);
            if known.is_none()
                || seen.iter().any(|(s, _, _)| *s == cs)
                || td_ta >> 4 > 1
                || td_ta & 0x0F > 1
            {
                return Err(nc(
                    "an SOS component is a distinct SOF0 component with baseline tables",
                ));
            }
            let tq = known.map_or(0, |(_, tq)| *tq);
            seen.push((cs, tq, td_ta));
        }
        let (ss, se, a) = (c.u8()?, c.u8()?, c.u8()?);
        if ss != 0 || se != 63 || a != 0 {
            return Err(nc("a baseline scan has Ss 0, Se 63, Ah = Al = 0"));
        }
        c.finish()?;
        for (cs, tq, td_ta) in seen {
            if self.scanned.contains(&cs) {
                return Err(nc(
                    "a component coded by two scans (baseline codes each once)",
                ));
            }
            if self.dqt & (1u8 << (tq & 0x03)) == 0 {
                return Err(nc(
                    "a scan whose component's quantisation table is not defined",
                ));
            }
            let dc = dht_bit(0, td_ta >> 4);
            let ac = dht_bit(1, td_ta & 0x0F);
            if self.dht & dc == 0 || self.dht & ac == 0 {
                return Err(nc("a scan naming a Huffman table not defined"));
            }
            self.scanned.push(cs);
        }
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
            components: u8::try_from(sof.components.len()).unwrap_or(0),
        })
    }
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
/// [`check`], and `canonicalize(canonicalize(x)) = canonicalize(x)`. It is the whole picture, so
/// it is a wiped buffer, sized once to the input (the output is never longer), and a refusal wipes
/// what was written before it (§10.5).
pub fn canonicalize(bytes: &[u8]) -> MediaResult<Zeroizing<Vec<u8>>> {
    let mut w = JpegWalker::new(JpegMode::Strip);
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    w.feed(bytes, Some(&mut out))?;
    w.finish()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(marker: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0xFF, marker];
        v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    const DQT0: [u8; 65] = [1; 65];

    /// One-code DC and AC tables, number `n`.
    fn dht_pair(n: u8) -> Vec<u8> {
        let mut v = Vec::new();
        for class in [0x00u8, 0x10] {
            v.push(class | n);
            v.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            v.push(0x00);
        }
        v
    }

    /// A minimal canonical grayscale JPEG of `w × h` (not a decodable picture).
    fn tiny(w: u16, h: u16) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8];
        let mut dqt = DQT0.to_vec();
        dqt[0] = 0x00;
        v.extend(seg(0xDB, &dqt));
        let mut sof = vec![0x08];
        sof.extend_from_slice(&h.to_be_bytes());
        sof.extend_from_slice(&w.to_be_bytes());
        sof.extend_from_slice(&[0x01, 0x01, 0x11, 0x00]);
        v.extend(seg(0xC0, &sof));
        v.extend(seg(0xC4, &dht_pair(0)));
        v.extend(seg(0xDA, &[0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]));
        v.extend_from_slice(&[0x12, 0xFF, 0x00, 0x34]);
        v.extend_from_slice(&[0xFF, 0xD9]);
        v
    }

    /// `tiny` with `extra` inserted before its SOS.
    fn before_sos(extra: &[u8]) -> Vec<u8> {
        let j = tiny(512, 512);
        let at = j.windows(2).position(|w| w == [0xFF, 0xDA]).expect("SOS");
        let mut m = j[..at].to_vec();
        m.extend_from_slice(extra);
        m.extend_from_slice(&j[at..]);
        m
    }

    fn rule(bytes: &[u8]) -> &'static str {
        check(bytes).expect_err("refused").rule()
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
        assert_eq!(*canonicalize(&j).expect("fixed point"), j);
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
        assert_eq!(*canonicalize(&with).expect("stripped"), j);
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

    #[test]
    fn every_table_once_every_component_once_and_tables_before_their_scan() {
        let mut dqt = DQT0.to_vec();
        dqt[0] = 0x00;
        assert_eq!(
            rule(&before_sos(&seg(0xDB, &dqt))),
            "a quantisation table defined twice"
        );
        dqt[0] = 0x01;
        check(&before_sos(&seg(0xDB, &dqt))).expect("a second table, Tq 1, defined once");
        assert_eq!(
            rule(&before_sos(&seg(0xC4, &dht_pair(0)[..18]))),
            "a Huffman table defined twice"
        );
        check(&before_sos(&seg(0xC4, &dht_pair(1)))).expect("tables 1, defined once");
        assert_eq!(
            rule(&before_sos(
                &[seg(0xDD, &[0, 4]), seg(0xDD, &[0, 4])].concat()
            )),
            "a second DRI"
        );
        // A second scan of the one component.
        let j = tiny(512, 512);
        let eoi = j.len() - 2;
        let mut twice = j[..eoi].to_vec();
        twice.extend(seg(0xDA, &[0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]));
        twice.extend_from_slice(&[0x12, 0xFF, 0xD9]);
        assert_eq!(
            rule(&twice),
            "a component coded by two scans (baseline codes each once)"
        );
        // Three components, one scan coding only the first.
        let mut three = vec![0xFF, 0xD8];
        let mut q = DQT0.to_vec();
        q[0] = 0x00;
        three.extend(seg(0xDB, &q));
        three.extend(seg(
            0xC0,
            &[8, 0, 16, 0, 16, 3, 1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0],
        ));
        three.extend(seg(0xC4, &dht_pair(0)));
        three.extend(seg(0xDA, &[0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]));
        three.extend_from_slice(&[0x12, 0xFF, 0xD9]);
        assert_eq!(
            rule(&three),
            "a SOF0 component that no scan codes (baseline codes each once)"
        );
        // A scan naming Huffman tables 1, which the file never defines.
        let mut undefined = tiny(512, 512);
        let sos = undefined
            .windows(2)
            .position(|w| w == [0xFF, 0xDA])
            .expect("SOS");
        undefined[sos + 6] = 0x11;
        assert_eq!(
            rule(&undefined),
            "a scan naming a Huffman table not defined"
        );
        // A component whose quantisation table (Tq 1) the file never defines.
        let mut no_q = tiny(512, 512);
        let sof = no_q
            .windows(2)
            .position(|w| w == [0xFF, 0xC0])
            .expect("SOF0");
        no_q[sof + 12] = 0x01;
        assert_eq!(
            rule(&no_q),
            "a scan whose component's quantisation table is not defined"
        );
    }

    #[test]
    fn the_walker_debug_never_renders_its_segment() {
        let mut w = JpegWalker::new(JpegMode::Check);
        let j = tiny(512, 512);
        let dqt_end = 2 + 4 + 40; // inside the DQT's 64 values of 1
        w.feed(&j[..dqt_end], None).expect("a prefix");
        let shown = format!("{:?}", JpegChecker(w));
        assert!(!shown.contains("1, 1, 1"), "{shown}");
    }
}
