//! The canonical fMP4 profile, its streaming walker and the `mfra` builder (design §8.3, written out
//! from the S0 goldens: S0-2, S0-3, S0-13, S0-20, S0-22).
//!
//! Top level exactly `ftyp`, `moov`, then (`moof`, `mdat`) pairs, then GHOST's `mfra`. The `moov` is
//! fixed but for the slots the profile names: which `trak` is audio (track IDs 1 and 2 in `trak`
//! order, one `soun`, one `vide`), the rotation matrix (0°, 90°, 180°, 270°, the same in both
//! `tkhd`), the `avcC` parameter sets (the SPS walked in full, `sps.rs`), the `colr` label ((5, 1, 6)
//! or (1, 1, 1), limited range) and the `esds` bitrate fields. Every other byte of the `moov` is the
//! value Media3 1.11.1's `FragmentedMp4Muxer` writes under GHOST's configuration, compared exactly.
//! Each `moof` is `mfhd` (sequence 1, 2, …) and one `traf` per track in track order, each exactly
//! `tfhd` (flags 0x1, `base_data_offset` = the `moof`'s offset), `tfdt` (version 1, the running sum
//! of the track's earlier `trun` durations) and `trun` (version 1, flags 0x701: no composition
//! offsets, so no B-frames), whose samples tile the following `mdat` in `traf` order with no gap;
//! one fragment's `moof` + `mdat` is at most 16 MiB. Video samples hold only NAL units of types 1,
//! 5, 6 (payload types 0, 1, 6), 7 and 8 (byte-identical to the `avcC` ones) and 9; a sample is a
//! sync sample exactly when it holds an IDR slice, and every fragment's first video sample is one.
//! Audio samples are opaque (Q35: AAC data elements are outside the walker's reach) but each is an
//! AAC-LC access unit of 1 024 samples and at most 1 536 bytes. `mfra` is exactly what
//! [`build_mfra`] builds from the walked fragments. `edts`, `udta`, `meta`, `ilst`, `keys`, `uuid`,
//! `free`, `skip`, `sidx`, `mehd` and any other box are refused.
//!
//! [`Fmp4Walker`] reads the stream in one pass with bounded memory (the `moov`, one `moof` and
//! one SEI at a time): the sealer feeds it the muxer's output (no `mfra` yet: the sealer appends the
//! one it builds), the reader the decrypted content (with the `mfra`). Each buffer is sized once to
//! the box or NAL unit it collects and wiped when dropped (§10.5); none renders in `Debug`.
//!
//! Bytes the profile does not constrain, each decoder syntax rather than a metadata field (declared,
//! §22.2 row 9): slice data, the PPS after its header (at most 512 B, the in-band copies
//! byte-identical to it), the bodies of the allowed SEI messages (at most 1 KiB per NAL unit), the
//! SPS values the walk reads without bounding, the `esds` buffer size and bitrates (11 B), and the
//! AAC frames (Q35).

use zeroize::Zeroizing;

use crate::bytes::{add, be_u32, extend_wiped, reserve_wiped, Cursor};
use crate::consts::{
    AAC_MAX_FRAME_BYTES, FRAGMENT_MAX_BYTES, MAX_FRAGMENTS, MOOF_MAX_BYTES, MOOV_MAX_BYTES,
    PARAMETER_SET_MAX_BYTES, SEI_MAX_BYTES, VIDEO_CODED_HEIGHT, VIDEO_CODED_WIDTH, VIDEO_MAX_MS,
};
use crate::error::{MediaError, MediaResult};
use crate::sps;

/// The video track's `mdhd` timescale.
pub const VIDEO_TIMESCALE: u32 = 90_000;
/// The audio track's `mdhd` timescale (48 kHz).
pub const AUDIO_TIMESCALE: u32 = 48_000;
/// An AAC-LC access unit's duration in the audio timescale.
pub const AAC_FRAME_DURATION: u32 = 1_024;
/// `trun` sample flags of a video sync sample (`sample_depends_on` 2).
pub const SYNC_FLAGS: u32 = 0x0200_0000;
/// `trun` sample flags of a video non-sync sample (`sample_depends_on` 1, `is_non_sync_sample`).
pub const NON_SYNC_FLAGS: u32 = 0x0101_0000;
/// The two colour labels of S0-13 (Q48): BT.601 limited as Media3 writes it, and BT.709 limited.
pub const COLOUR_LABELS: [(u16, u16, u16); 2] = [(5, 1, 6), (1, 1, 1)];

const FTYP_BODY: [u8; 20] = *b"isom\x00\x02\x00\x00isomiso2mp41";
const IDENTITY: [u32; 9] = [0x0001_0000, 0, 0, 0, 0x0001_0000, 0, 0, 0, 0x4000_0000];
const ROT90: [u32; 9] = [0, 0x0001_0000, 0, 0xFFFF_0000, 0, 0, 0, 0, 0x4000_0000];
const ROT180: [u32; 9] = [0xFFFF_0000, 0, 0, 0, 0xFFFF_0000, 0, 0, 0, 0x4000_0000];
const ROT270: [u32; 9] = [0, 0xFFFF_0000, 0, 0x0001_0000, 0, 0, 0, 0, 0x4000_0000];

fn nc(rule: &'static str) -> MediaError {
    MediaError::non_canonical(rule)
}

/// One `tfra` entry: a `moof`'s offset in the content and its video `tfdt`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MoofEntry {
    /// The `moof`'s offset from the start of the content.
    pub offset: u64,
    /// The video `traf`'s `tfdt`, in the video timescale.
    pub video_time: u64,
}

/// What the walker reports about a canonical stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fmp4Info {
    /// The displayed width: the coded 1 280 × 720 turned by the `tkhd` matrix (S0-20).
    pub width: u16,
    /// The displayed height.
    pub height: u16,
    /// The rotation of the `tkhd` matrix: 0, 90, 180 or 270.
    pub rotation: u16,
    /// The video track's summed `trun` durations, rounded down to milliseconds (§3.5).
    pub duration_ms: u32,
    /// The `colr` label `(primaries, transfer, matrix)`.
    pub colour: (u16, u16, u16),
    /// The SPS `profile_idc`: 66 or 100.
    pub profile_idc: u8,
    /// The video track's ID (1 or 2).
    pub video_track: u32,
    /// Every `moof`, in order: the `mfra` entries.
    pub moofs: Vec<MoofEntry>,
}

/// Whether the stream ends after its last `mdat` (the sealer's input) or with GHOST's `mfra` (an
/// object's content).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fmp4Mode {
    Sealer,
    Reader,
}

/// `mfra` = `tfra` (version 1, the video track, 1-byte traf/trun/sample numbers, one entry per
/// `moof` with its video `tfdt` and offset, traf/trun/sample number 1) + `mfro` (§8.3, S0-2).
pub fn build_mfra(video_track: u32, moofs: &[MoofEntry]) -> Vec<u8> {
    let entries = moofs.len();
    let tfra_size = 24usize.saturating_add(entries.saturating_mul(19));
    let mfra_size = 8usize.saturating_add(tfra_size).saturating_add(16);
    let mut out = Vec::with_capacity(mfra_size);
    let mfra32 = u32::try_from(mfra_size).unwrap_or(u32::MAX);
    out.extend_from_slice(&mfra32.to_be_bytes());
    out.extend_from_slice(b"mfra");
    out.extend_from_slice(&u32::try_from(tfra_size).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(b"tfra");
    out.extend_from_slice(&[0x01, 0, 0, 0]);
    out.extend_from_slice(&video_track.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&u32::try_from(entries).unwrap_or(u32::MAX).to_be_bytes());
    for m in moofs {
        out.extend_from_slice(&m.video_time.to_be_bytes());
        out.extend_from_slice(&m.offset.to_be_bytes());
        out.extend_from_slice(&[1, 1, 1]);
    }
    out.extend_from_slice(&16u32.to_be_bytes());
    out.extend_from_slice(b"mfro");
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&mfra32.to_be_bytes());
    out
}

/// The streaming form of [`check`] (an object's content, `mfra` included): the stream in pieces of
/// any size gives the result one piece gives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fmp4Checker(Fmp4Walker);

impl Default for Fmp4Checker {
    fn default() -> Self {
        Fmp4Checker(Fmp4Walker::new(Fmp4Mode::Reader))
    }
}

impl Fmp4Checker {
    /// A checker at the start of a stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Walks the next bytes.
    pub fn feed(&mut self, data: &[u8]) -> MediaResult<()> {
        self.0.feed(data)
    }

    /// The walk's report, once the stream ended exactly after its `mfra`.
    pub fn finish(&self) -> MediaResult<Fmp4Info> {
        self.0.finish()
    }
}

/// Checks that `bytes` is exactly one canonical stream, `mfra` included, and reports it.
pub fn check(bytes: &[u8]) -> MediaResult<Fmp4Info> {
    let mut w = Fmp4Walker::new(Fmp4Mode::Reader);
    w.feed(bytes)?;
    w.finish()
}

// ---------------------------------------------------------------------------------------------
// The moov.

#[derive(Clone, PartialEq, Eq)]
struct Moov {
    /// `video[i]`: whether track ID `i + 1` is the video track.
    video: [bool; 2],
    rotation: u16,
    colour: (u16, u16, u16),
    profile_idc: u8,
    sps: Zeroizing<Vec<u8>>,
    pps: Zeroizing<Vec<u8>>,
}

impl Moov {
    fn video_track(&self) -> u32 {
        if self.video[0] {
            1
        } else {
            2
        }
    }
}

/// The child boxes of `body`, which they must tile exactly.
fn children(body: &[u8]) -> MediaResult<Vec<([u8; 4], &[u8])>> {
    let mut out = Vec::new();
    let mut c = Cursor::new(body, "a box that does not tile its parent");
    while !c.is_empty() {
        let size = c.u32()?;
        let typ: [u8; 4] = c.array()?;
        if size < 8 {
            return Err(nc(
                "a box whose size is below 8 (or a largesize or to-end box)",
            ));
        }
        let len = usize::try_from(size.saturating_sub(8)).map_err(|_| nc("a box too large"))?;
        out.push((typ, c.take(len)?));
    }
    Ok(out)
}

/// The children of `body`, which must be exactly `want`, in order.
fn expect_children<'a>(
    body: &'a [u8],
    want: &[&[u8; 4]],
    rule: &'static str,
) -> MediaResult<Vec<&'a [u8]>> {
    let kids = children(body)?;
    if kids.len() != want.len() || kids.iter().zip(want.iter()).any(|((t, _), w)| t != *w) {
        return Err(nc(rule));
    }
    Ok(kids.into_iter().map(|(_, b)| b).collect())
}

fn exact(body: &[u8], want: &[u8], rule: &'static str) -> MediaResult<()> {
    if body == want {
        Ok(())
    } else {
        Err(nc(rule))
    }
}

fn mvhd_body() -> Vec<u8> {
    let mut v = vec![0u8; 12];
    v.extend_from_slice(&10_000u32.to_be_bytes()); // timescale
    v.extend_from_slice(&[0, 0, 0, 0]); // duration
    v.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // rate 1.0
    v.extend_from_slice(&[0x01, 0x00]); // volume 1.0
    v.extend_from_slice(&[0u8; 10]); // reserved
    for m in IDENTITY {
        v.extend_from_slice(&m.to_be_bytes());
    }
    v.extend_from_slice(&[0u8; 24]); // pre_defined
    v.extend_from_slice(&3u32.to_be_bytes()); // next_track_ID
    v
}

fn tkhd_body(id: u32, video: bool, matrix: &[u32; 9]) -> Vec<u8> {
    let mut v = vec![0x00, 0x00, 0x00, 0x07];
    v.extend_from_slice(&[0u8; 8]); // creation, modification
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(&[0u8; 16]); // reserved, duration, reserved
    v.extend_from_slice(&[0u8; 4]); // layer, alternate_group
    v.extend_from_slice(if video { &[0x00, 0x00] } else { &[0x01, 0x00] }); // volume
    v.extend_from_slice(&[0u8; 2]);
    for m in matrix {
        v.extend_from_slice(&m.to_be_bytes());
    }
    if video {
        v.extend_from_slice(&(u32::from(VIDEO_CODED_WIDTH) << 16).to_be_bytes());
        v.extend_from_slice(&(u32::from(VIDEO_CODED_HEIGHT) << 16).to_be_bytes());
    } else {
        v.extend_from_slice(&[0u8; 8]);
    }
    v
}

fn mdhd_body(timescale: u32) -> Vec<u8> {
    let mut v = vec![0u8; 12];
    v.extend_from_slice(&timescale.to_be_bytes());
    v.extend_from_slice(&[0u8; 8]); // duration, language, pre_defined
    v
}

fn hdlr_body(video: bool) -> Vec<u8> {
    let mut v = vec![0u8; 8];
    v.extend_from_slice(if video { b"vide" } else { b"soun" });
    v.extend_from_slice(&[0u8; 12]);
    v.extend_from_slice(if video {
        b"VideoHandle\0"
    } else {
        b"SoundHandle\0"
    });
    v
}

const DREF_BODY: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 12, b'u', b'r', b'l', b' ', 0, 0, 0, 1,
];

fn avc1_fixed() -> Vec<u8> {
    let mut v = vec![0u8; 6];
    v.extend_from_slice(&[0x00, 0x01]); // data_reference_index
    v.extend_from_slice(&[0u8; 16]); // pre_defined, reserved, pre_defined
    v.extend_from_slice(&VIDEO_CODED_WIDTH.to_be_bytes());
    v.extend_from_slice(&VIDEO_CODED_HEIGHT.to_be_bytes());
    v.extend_from_slice(&0x0048_0000u32.to_be_bytes()); // 72 dpi
    v.extend_from_slice(&0x0048_0000u32.to_be_bytes());
    v.extend_from_slice(&[0u8; 4]);
    v.extend_from_slice(&[0x00, 0x01]); // frame_count
    v.extend_from_slice(&[0u8; 32]); // compressorname
    v.extend_from_slice(&[0x00, 0x18, 0xFF, 0xFF]); // depth 24, pre_defined -1
    v
}

fn mp4a_fixed() -> Vec<u8> {
    let mut v = vec![0u8; 6];
    v.extend_from_slice(&[0x00, 0x01]); // data_reference_index
    v.extend_from_slice(&[0u8; 8]);
    v.extend_from_slice(&[0x00, 0x02, 0x00, 0x10]); // 2 channels, 16-bit
    v.extend_from_slice(&[0u8; 4]);
    v.extend_from_slice(&(AUDIO_TIMESCALE << 16).to_be_bytes());
    v
}

fn rotation_of(matrix: &[u32; 9]) -> Option<u16> {
    if *matrix == IDENTITY {
        Some(0)
    } else if *matrix == ROT90 {
        Some(90)
    } else if *matrix == ROT180 {
        Some(180)
    } else if *matrix == ROT270 {
        Some(270)
    } else {
        None
    }
}

/// An `avcC`'s profile and its two parameter sets.
type Avc = (u8, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

struct Trak {
    id: u32,
    video: bool,
    matrix: [u32; 9],
    colour: Option<(u16, u16, u16)>,
    avc: Option<Avc>,
}

fn parse_trak(body: &[u8]) -> MediaResult<Trak> {
    let k = expect_children(body, &[b"tkhd", b"mdia"], "a trak is exactly tkhd, mdia")?;
    let (tkhd, mdia) = (
        k.first().copied().unwrap_or(&[]),
        k.get(1).copied().unwrap_or(&[]),
    );
    let m = expect_children(
        mdia,
        &[b"mdhd", b"hdlr", b"minf"],
        "an mdia is mdhd, hdlr, minf",
    )?;
    let (mdhd, hdlr, minf) = (
        m.first().copied().unwrap_or(&[]),
        m.get(1).copied().unwrap_or(&[]),
        m.get(2).copied().unwrap_or(&[]),
    );
    let video = if hdlr == hdlr_body(true).as_slice() {
        true
    } else if hdlr == hdlr_body(false).as_slice() {
        false
    } else {
        return Err(nc(
            "an hdlr other than soun SoundHandle or vide VideoHandle",
        ));
    };
    // tkhd: the track ID and the matrix are the only slots.
    let mut c = Cursor::new(tkhd, "a malformed tkhd");
    c.take(12)?;
    let id = c.u32()?;
    c.take(24)?;
    let mut matrix = [0u32; 9];
    for m in matrix.iter_mut() {
        *m = c.u32()?;
    }
    if rotation_of(&matrix).is_none() {
        return Err(nc("a tkhd matrix other than 0, 90, 180 or 270 degrees"));
    }
    exact(
        tkhd,
        &tkhd_body(id, video, &matrix),
        "a tkhd that is not v0, flags 7, times and duration 0 (with the track's volume and size)",
    )?;
    let timescale = if video {
        VIDEO_TIMESCALE
    } else {
        AUDIO_TIMESCALE
    };
    exact(
        mdhd,
        &mdhd_body(timescale),
        "an mdhd that is not v0, times 0, 48 000 or 90 000",
    )?;
    let media_header: &[u8; 4] = if video { b"vmhd" } else { b"smhd" };
    let i = expect_children(
        minf,
        &[media_header, b"dinf", b"stbl"],
        "a minf is xmhd, dinf, stbl",
    )?;
    let (xmhd, dinf, stbl) = (
        i.first().copied().unwrap_or(&[]),
        i.get(1).copied().unwrap_or(&[]),
        i.get(2).copied().unwrap_or(&[]),
    );
    let zero_header: &[u8] = if video { &[0u8; 12] } else { &[0u8; 8] };
    exact(xmhd, zero_header, "a vmhd or smhd that is not zero")?;
    let d = expect_children(dinf, &[b"dref"], "a dinf is one dref")?;
    exact(
        d.first().copied().unwrap_or(&[]),
        &DREF_BODY,
        "a dref that is not one self-reference",
    )?;
    let want: &[&[u8; 4]] = if video {
        &[b"stsd", b"stts", b"stsz", b"stsc", b"stco", b"stss"]
    } else {
        &[b"stsd", b"stts", b"stsz", b"stsc", b"stco"]
    };
    let s = expect_children(
        stbl,
        want,
        "an stbl is stsd, stts, stsz, stsc, stco (and stss for video)",
    )?;
    for (n, b) in s.iter().enumerate().skip(1) {
        let zero: &[u8] = if n == 2 { &[0u8; 12] } else { &[0u8; 8] };
        exact(b, zero, "a sample table that is not empty")?;
    }
    let stsd = s.first().copied().unwrap_or(&[]);
    let mut c = Cursor::new(stsd, "a malformed stsd");
    if c.array::<8>()? != [0, 0, 0, 0, 0, 0, 0, 1] {
        return Err(nc("an stsd with other than one entry"));
    }
    let entries = children(c.rest())?;
    let [(typ, entry)] = entries.as_slice() else {
        return Err(nc("an stsd with other than one entry"));
    };
    let mut trak = Trak {
        id,
        video,
        matrix,
        colour: None,
        avc: None,
    };
    if video {
        if typ != b"avc1" {
            return Err(nc("a video sample entry other than avc1"));
        }
        let fixed = avc1_fixed();
        let (head, rest) = entry.split_at(entry.len().min(fixed.len()));
        exact(
            head,
            &fixed,
            "an avc1 entry that is not coded 1 280 × 720 with Media3's fields",
        )?;
        let e = expect_children(
            rest,
            &[b"avcC", b"pasp", b"colr"],
            "an avc1 holds avcC, pasp, colr",
        )?;
        exact(
            e.get(1).copied().unwrap_or(&[]),
            &[0, 1, 0, 0, 0, 1, 0, 0],
            "a pasp other than 65 536 : 65 536",
        )?;
        let colour = parse_colr(e.get(2).copied().unwrap_or(&[]))?;
        trak.colour = Some(colour);
        trak.avc = Some(parse_avcc(e.first().copied().unwrap_or(&[]), colour)?);
    } else {
        if typ != b"mp4a" {
            return Err(nc("an audio sample entry other than mp4a"));
        }
        let fixed = mp4a_fixed();
        let (head, rest) = entry.split_at(entry.len().min(fixed.len()));
        exact(
            head,
            &fixed,
            "an mp4a entry that is not 48 kHz stereo 16-bit",
        )?;
        let e = expect_children(rest, &[b"esds"], "an mp4a holds one esds")?;
        parse_esds(e.first().copied().unwrap_or(&[]))?;
    }
    Ok(trak)
}

fn parse_colr(body: &[u8]) -> MediaResult<(u16, u16, u16)> {
    let mut c = Cursor::new(body, "a malformed colr");
    if &c.array::<4>()? != b"nclx" {
        return Err(nc("a colr other than nclx"));
    }
    let t = (c.u16()?, c.u16()?, c.u16()?);
    let range = c.u8()?;
    c.finish()?;
    if range != 0 || !COLOUR_LABELS.contains(&t) {
        return Err(nc(
            "a colr other than (5, 1, 6) or (1, 1, 1), limited range (S0-13)",
        ));
    }
    Ok(t)
}

fn parse_esds(body: &[u8]) -> MediaResult<()> {
    // ES_Descriptor (one-byte lengths, as Media3 writes them) with a DecoderConfigDescriptor for
    // MPEG-4 audio, the AudioSpecificConfig 0x1190 (AAC-LC, 48 kHz, two channels) and the
    // predefined SLConfig 2. The buffer size and the two bitrates are the encoder's values.
    let mut c = Cursor::new(body, "a malformed esds");
    let head = c.array::<13>()?;
    if head != [0, 0, 0, 0, 0x03, 0x19, 0, 0, 0, 0x04, 0x11, 0x40, 0x15] {
        return Err(nc("an esds that is not an MPEG-4 audio ES descriptor"));
    }
    c.take(11)?; // bufferSizeDB (3), maxBitrate (4), avgBitrate (4)
    let tail = c.array::<7>()?;
    c.finish()?;
    if tail != [0x05, 0x02, 0x11, 0x90, 0x06, 0x01, 0x02] {
        return Err(nc(
            "an AudioSpecificConfig other than 0x1190 (AAC-LC, 48 kHz, stereo)",
        ));
    }
    Ok(())
}

fn parse_avcc(body: &[u8], colour: (u16, u16, u16)) -> MediaResult<Avc> {
    let mut c = Cursor::new(body, "a malformed avcC");
    let version = c.u8()?;
    let indication = c.array::<3>()?;
    let (len_size, sps_count) = (c.u8()?, c.u8()?);
    if version != 1 || len_size != 0xFF || sps_count != 0xE1 {
        return Err(nc(
            "an avcC that is not version 1 with 4-byte lengths and one SPS",
        ));
    }
    let sps_len = c.u16()?;
    if sps_len == 0 || sps_len > PARAMETER_SET_MAX_BYTES {
        return Err(nc("an SPS length outside 1 … 512"));
    }
    let sps_nal = Zeroizing::new(c.take(usize::from(sps_len))?.to_vec());
    if c.u8()? != 1 {
        return Err(nc("an avcC with other than one PPS"));
    }
    let pps_len = c.u16()?;
    if !(2..=PARAMETER_SET_MAX_BYTES).contains(&pps_len) {
        return Err(nc("a PPS length outside 2 … 512"));
    }
    let pps_nal = Zeroizing::new(c.take(usize::from(pps_len))?.to_vec());
    let info = sps::walk(&sps_nal)?;
    if sps_nal.get(1..4) != Some(indication.as_slice()) {
        return Err(nc(
            "avcC profile, compatibility and level that are not the SPS's",
        ));
    }
    let pps_header = pps_nal.first().copied().unwrap_or(0);
    if pps_header & 0x80 != 0 || pps_header & 0x1F != 8 || pps_header & 0x60 == 0 {
        return Err(nc("a PPS NAL header that is not a reference NAL of type 8"));
    }
    // A High-profile avcC may carry the ISO/IEC 14496-15 extension for 4:2:0 8-bit and no SPS
    // extension; Baseline carries none.
    let rest = c.rest();
    let ext_ok = rest.is_empty() || (info.profile_idc == 100 && rest == [0xFD, 0xF8, 0xF8, 0x00]);
    if !ext_ok {
        return Err(nc("bytes after the avcC parameter sets"));
    }
    if let Some((p, t, m)) = info.colour {
        if (u16::from(p), u16::from(t), u16::from(m)) != colour {
            return Err(nc(
                "an SPS colour description other than the colr box's (S0-13)",
            ));
        }
    }
    Ok((info.profile_idc, sps_nal, pps_nal))
}

fn parse_moov(body: &[u8]) -> MediaResult<Moov> {
    let k = expect_children(
        body,
        &[b"mvhd", b"trak", b"trak", b"mvex"],
        "a moov is exactly mvhd, trak, trak, mvex (one audio and one video track)",
    )?;
    exact(
        k.first().copied().unwrap_or(&[]),
        &mvhd_body(),
        "an mvhd that is not v0, times 0, timescale 10 000, duration 0, next track 3",
    )?;
    let a = parse_trak(k.get(1).copied().unwrap_or(&[]))?;
    let b = parse_trak(k.get(2).copied().unwrap_or(&[]))?;
    if a.id != 1 || b.id != 2 {
        return Err(nc("track IDs that are not 1 and 2 in trak order"));
    }
    if a.video == b.video {
        return Err(nc("tracks that are not one soun and one vide"));
    }
    if a.matrix != b.matrix {
        return Err(nc("two tkhd with different matrices"));
    }
    let rotation = rotation_of(&a.matrix).unwrap_or(0);
    let video = if a.video { &a } else { &b };
    let (Some(colour), Some((profile_idc, sps, pps))) = (video.colour, video.avc.clone()) else {
        return Err(nc("a video track without its sample entry"));
    };
    let x = expect_children(
        k.get(3).copied().unwrap_or(&[]),
        &[b"trex", b"trex"],
        "an mvex is two trex",
    )?;
    for (n, t) in x.iter().enumerate() {
        let id = u32::try_from(n).unwrap_or(0).saturating_add(1);
        let mut want = vec![0u8; 4];
        want.extend_from_slice(&id.to_be_bytes());
        want.extend_from_slice(&[0, 0, 0, 1]);
        want.extend_from_slice(&[0u8; 12]);
        exact(
            t,
            &want,
            "a trex that is not the track's defaults (1, 0, 0, 0)",
        )?;
    }
    Ok(Moov {
        video: [a.video, b.video],
        rotation,
        colour,
        profile_idc,
        sps,
        pps,
    })
}

// ---------------------------------------------------------------------------------------------
// The fragments.

#[derive(Clone, Debug, PartialEq, Eq)]
struct Run {
    video: bool,
    /// `(size, sync)` per sample.
    samples: Vec<(u32, bool)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParamSet {
    Sps,
    Pps,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Nal {
    Len { have: u8, value: u32 },
    Header { len: u32 },
    Skip { left: u32 },
    Sei { left: u32 },
    Same { which: ParamSet, at: u32, left: u32 },
    Aud,
}

#[derive(Clone, PartialEq, Eq)]
struct Mdat {
    runs: Vec<Run>,
    run: usize,
    sample: usize,
    sample_left: u32,
    nal: Nal,
    saw_idr: bool,
    sei: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Collecting {
    Ftyp,
    Moov,
    Moof,
    Mfra,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Next {
    Ftyp,
    Moov,
    Moof,
    Mdat,
    MoofOrEnd,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Stage {
    Header { have: u8, buf: [u8; 8] },
    Collect { what: Collecting, left: u32 },
    Mdat,
    End,
}

/// The streaming walker of the canonical fMP4 profile.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Fmp4Walker {
    mode: Fmp4Mode,
    pos: u64,
    stage: Stage,
    next: Next,
    boxbuf: Zeroizing<Vec<u8>>,
    box_start: u64,
    moov: Option<Moov>,
    next_seq: u32,
    decode_time: [u64; 2],
    moofs: Vec<MoofEntry>,
    /// The current fragment's `moof` size and expected `mdat` payload.
    moof_size: u64,
    mdat_payload: u64,
    mdat: Option<Mdat>,
    /// The first refusal: every later call repeats it.
    failed: Option<MediaError>,
}

impl core::fmt::Debug for Fmp4Walker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The box, SEI and parameter-set buffers hold the stream's own bytes: none renders.
        f.debug_struct("Fmp4Walker")
            .field("mode", &self.mode)
            .field("pos", &self.pos)
            .field("next", &self.next)
            .field("fragments", &self.moofs.len())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl Fmp4Walker {
    pub(crate) fn new(mode: Fmp4Mode) -> Self {
        Fmp4Walker {
            mode,
            pos: 0,
            stage: Stage::Header {
                have: 0,
                buf: [0; 8],
            },
            next: Next::Ftyp,
            boxbuf: Zeroizing::new(Vec::new()),
            box_start: 0,
            moov: None,
            next_seq: 1,
            decode_time: [0, 0],
            moofs: Vec::new(),
            moof_size: 0,
            mdat_payload: 0,
            mdat: None,
            failed: None,
        }
    }

    /// Feeds the next bytes of the stream.
    pub(crate) fn feed(&mut self, data: &[u8]) -> MediaResult<()> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let result = self.feed_inner(data);
        if let Err(e) = result {
            self.failed = Some(e);
        }
        result
    }

    fn feed_inner(&mut self, data: &[u8]) -> MediaResult<()> {
        let mut i = 0usize;
        while let Some(rest) = data.get(i..) {
            if rest.is_empty() {
                break;
            }
            let used = match self.stage.clone() {
                Stage::Header { have, mut buf } => {
                    if have == 0 {
                        self.box_start = self.pos;
                    }
                    let need = 8usize.saturating_sub(usize::from(have));
                    let n = need.min(rest.len());
                    for (k, b) in rest.iter().take(n).enumerate() {
                        if let Some(slot) = buf.get_mut(usize::from(have).saturating_add(k)) {
                            *slot = *b;
                        }
                    }
                    let have = have.saturating_add(u8::try_from(n).unwrap_or(8));
                    self.stage = Stage::Header { have, buf };
                    if have == 8 {
                        self.header(buf)?;
                        if let Stage::Collect { what, left: 0 } = self.stage {
                            self.collected(what)?;
                        }
                    }
                    n
                }
                Stage::Collect { what, left } => {
                    let n = usize::try_from(left).unwrap_or(usize::MAX).min(rest.len());
                    extend_wiped(&mut self.boxbuf, rest.get(..n).unwrap_or(&[]));
                    let left = left.saturating_sub(u32::try_from(n).unwrap_or(u32::MAX));
                    self.stage = Stage::Collect { what, left };
                    if left == 0 {
                        self.collected(what)?;
                    }
                    n
                }
                Stage::Mdat => self.mdat_bytes(rest)?,
                Stage::End => return Err(nc("bytes after the mfra")),
            };
            i = i.saturating_add(used);
            self.pos = add(
                self.pos,
                u64::try_from(used).unwrap_or(u64::MAX),
                "a stream too long",
            )?;
        }
        Ok(())
    }

    fn header(&mut self, buf: [u8; 8]) -> MediaResult<()> {
        let size = be_u32(&buf, 0).unwrap_or(0);
        let typ = [
            buf.get(4).copied().unwrap_or(0),
            buf.get(5).copied().unwrap_or(0),
            buf.get(6).copied().unwrap_or(0),
            buf.get(7).copied().unwrap_or(0),
        ];
        if size < 8 {
            return Err(nc(
                "a box whose size is below 8 (or a largesize or to-end box)",
            ));
        }
        let body = size.saturating_sub(8);
        let collect = |what: Collecting, s: &mut Self| {
            // The whole box's room at once (each box's size is bounded before this): the buffer
            // never grows while it fills.
            s.boxbuf.clear();
            reserve_wiped(&mut s.boxbuf, usize::try_from(size).unwrap_or(0));
            s.boxbuf.extend_from_slice(&buf);
            s.stage = Stage::Collect { what, left: body };
        };
        match (self.next, &typ) {
            (Next::Ftyp, b"ftyp") => {
                if size != 28 {
                    return Err(nc("an ftyp other than (isom, 131 072, isom iso2 mp41)"));
                }
                collect(Collecting::Ftyp, self);
            }
            (Next::Moov, b"moov") => {
                if size > MOOV_MAX_BYTES {
                    return Err(nc("a moov above 64 KiB"));
                }
                collect(Collecting::Moov, self);
            }
            (Next::Moof | Next::MoofOrEnd, b"moof") => {
                if self.moofs.len() >= MAX_FRAGMENTS {
                    return Err(nc("more than 1 024 fragments"));
                }
                if size > MOOF_MAX_BYTES {
                    return Err(nc("a moof above 256 KiB"));
                }
                self.moof_size = u64::from(size);
                collect(Collecting::Moof, self);
            }
            (Next::Mdat, b"mdat") => {
                if u64::from(size) != self.mdat_payload.saturating_add(8) {
                    return Err(nc("an mdat whose size is not its trafs' samples"));
                }
                if self.moof_size.saturating_add(u64::from(size)) > FRAGMENT_MAX_BYTES {
                    return Err(nc("a fragment (moof + mdat) above 16 MiB (Q46)"));
                }
                self.stage = Stage::Mdat;
            }
            (Next::MoofOrEnd, b"mfra") if self.mode == Fmp4Mode::Reader => {
                let video_track = self.moov.as_ref().map_or(0, Moov::video_track);
                let want = build_mfra(video_track, &self.moofs);
                if usize::try_from(size).ok() != Some(want.len()) {
                    return Err(nc("an mfra other than GHOST's (S0-2)"));
                }
                collect(Collecting::Mfra, self);
            }
            (_, b"mfra") if self.mode == Fmp4Mode::Sealer => {
                return Err(nc(
                    "an mfra in the sealer's input (the sealer appends its own)",
                ));
            }
            _ => {
                return Err(nc(
                    "a top-level box outside ftyp, moov, (moof, mdat)+, mfra",
                ))
            }
        }
        Ok(())
    }

    fn collected(&mut self, what: Collecting) -> MediaResult<()> {
        // Moved out whole and wiped when it drops at the end of this call.
        let whole = core::mem::take(&mut self.boxbuf);
        let body = whole.get(8..).unwrap_or(&[]);
        match what {
            Collecting::Ftyp => {
                exact(
                    body,
                    &FTYP_BODY,
                    "an ftyp other than (isom, 131 072, isom iso2 mp41)",
                )?;
                self.next = Next::Moov;
            }
            Collecting::Moov => {
                self.moov = Some(parse_moov(body)?);
                self.next = Next::Moof;
            }
            Collecting::Moof => {
                self.parse_moof(body)?;
                self.next = Next::Mdat;
            }
            Collecting::Mfra => {
                let video_track = self.moov.as_ref().map_or(0, Moov::video_track);
                exact(
                    &whole,
                    &build_mfra(video_track, &self.moofs),
                    "an mfra other than GHOST's (S0-2)",
                )?;
                self.stage = Stage::End;
                return Ok(());
            }
        }
        self.stage = Stage::Header {
            have: 0,
            buf: [0; 8],
        };
        Ok(())
    }

    fn parse_moof(&mut self, body: &[u8]) -> MediaResult<()> {
        let moov = self
            .moov
            .as_ref()
            .ok_or_else(|| nc("a moof before the moov"))?;
        let moof_offset = self.box_start;
        let k = expect_children(
            body,
            &[b"mfhd", b"traf", b"traf"],
            "a moof is mfhd and one traf per track",
        )?;
        let mut want_mfhd = vec![0u8; 4];
        want_mfhd.extend_from_slice(&self.next_seq.to_be_bytes());
        exact(
            k.first().copied().unwrap_or(&[]),
            &want_mfhd,
            "an mfhd sequence out of order",
        )?;
        self.next_seq = self.next_seq.saturating_add(1);
        let mdat_start = add(moof_offset, self.moof_size, "a stream too long")?;
        let mut cursor = add(mdat_start, 8, "a stream too long")?;
        let mut runs = Vec::with_capacity(2);
        let mut video_time = 0u64;
        for (t, traf) in k.iter().skip(1).enumerate() {
            let track = u32::try_from(t).unwrap_or(0).saturating_add(1);
            let video = moov.video.get(t).copied().unwrap_or(false);
            let p = expect_children(
                traf,
                &[b"tfhd", b"tfdt", b"trun"],
                "a traf is exactly tfhd, tfdt, trun (S0-2)",
            )?;
            let mut want_tfhd = vec![0, 0, 0, 1];
            want_tfhd.extend_from_slice(&track.to_be_bytes());
            want_tfhd.extend_from_slice(&moof_offset.to_be_bytes());
            exact(
                p.first().copied().unwrap_or(&[]),
                &want_tfhd,
                "a tfhd that is not flags 0x1 with the moof's offset, in track order",
            )?;
            let time = self.decode_time.get(t).copied().unwrap_or(0);
            let mut want_tfdt = vec![1, 0, 0, 0];
            want_tfdt.extend_from_slice(&time.to_be_bytes());
            exact(
                p.get(1).copied().unwrap_or(&[]),
                &want_tfdt,
                "a tfdt that is not version 1 with the running sum of the track's durations (S0-2)",
            )?;
            if video {
                video_time = time;
            }
            let trun = p.get(2).copied().unwrap_or(&[]);
            let mut c = Cursor::new(trun, "a malformed trun");
            if c.array::<4>()? != [0x01, 0x00, 0x07, 0x01] {
                return Err(nc(
                    "a trun other than version 1, flags 0x701 (no composition offsets)",
                ));
            }
            let count = c.u32()?;
            let data_offset = c.u32()?;
            if count == 0 {
                return Err(nc("a trun without samples"));
            }
            let start = add(moof_offset, u64::from(data_offset), "a stream too long")?;
            if start != cursor {
                return Err(nc("trun data that does not tile the mdat in traf order"));
            }
            let mut samples = Vec::new();
            let mut duration_sum = 0u64;
            for n in 0..count {
                let (duration, size, flags) = (c.u32()?, c.u32()?, c.u32()?);
                if video {
                    let sync = match flags {
                        SYNC_FLAGS => true,
                        NON_SYNC_FLAGS => false,
                        _ => return Err(nc("video sample flags other than sync or non-sync")),
                    };
                    if n == 0 && !sync {
                        return Err(nc(
                            "a fragment whose first video sample is not a sync sample",
                        ));
                    }
                    if duration == 0 || size < 5 {
                        return Err(nc("a video sample of zero duration or without a NAL unit"));
                    }
                    samples.push((size, sync));
                } else {
                    if duration != AAC_FRAME_DURATION || flags != SYNC_FLAGS {
                        return Err(nc("an audio sample that is not one AAC-LC access unit"));
                    }
                    if size == 0 || size > AAC_MAX_FRAME_BYTES {
                        return Err(nc("an AAC access unit of 0 or more than 1 536 bytes"));
                    }
                    samples.push((size, true));
                }
                duration_sum = add(duration_sum, u64::from(duration), "durations too long")?;
                cursor = add(cursor, u64::from(size), "a stream too long")?;
            }
            c.finish()?;
            if let Some(d) = self.decode_time.get_mut(t) {
                *d = add(*d, duration_sum, "durations too long")?;
            }
            runs.push(Run { video, samples });
        }
        let total_video = self
            .decode_time
            .get(usize::from(!moov.video[0]))
            .copied()
            .unwrap_or(0);
        if total_video > u64::from(VIDEO_MAX_MS).saturating_add(1).saturating_mul(90) {
            return Err(nc("a video longer than VIDEO_MAX_MS"));
        }
        self.mdat_payload = cursor.saturating_sub(mdat_start).saturating_sub(8);
        self.moofs.push(MoofEntry {
            offset: moof_offset,
            video_time,
        });
        let first = runs
            .first()
            .and_then(|r| r.samples.first())
            .map_or(0, |s| s.0);
        self.mdat = Some(Mdat {
            runs,
            run: 0,
            sample: 0,
            sample_left: first,
            nal: Nal::Len { have: 0, value: 0 },
            saw_idr: false,
            sei: Zeroizing::new(Vec::new()),
        });
        Ok(())
    }

    /// Consumes mdat payload bytes; returns how many of `rest` it used.
    fn mdat_bytes(&mut self, rest: &[u8]) -> MediaResult<usize> {
        let moov = self
            .moov
            .as_ref()
            .ok_or_else(|| nc("an mdat before the moov"))?;
        let mut m = self
            .mdat
            .take()
            .ok_or_else(|| nc("an mdat without its moof"))?;
        let mut used = 0usize;
        let mut done = false;
        while let Some(avail) = rest.get(used..) {
            if avail.is_empty() {
                break;
            }
            let video = m
                .runs
                .get(m.run)
                .ok_or_else(|| nc("mdat bytes beyond the trafs' samples"))?
                .video;
            let take = usize::try_from(m.sample_left)
                .unwrap_or(usize::MAX)
                .min(avail.len());
            let piece = avail.get(..take).unwrap_or(&[]);
            if video {
                let mut k = 0usize;
                while k < piece.len() {
                    // Bytes left in the sample at offset k of the piece.
                    let here = m
                        .sample_left
                        .saturating_sub(u32::try_from(k).unwrap_or(u32::MAX));
                    let step = nal_step(moov, &mut m, piece.get(k..).unwrap_or(&[]), here)?;
                    k = k.saturating_add(step);
                }
            }
            used = used.saturating_add(take);
            m.sample_left = m
                .sample_left
                .saturating_sub(u32::try_from(take).unwrap_or(u32::MAX));
            if m.sample_left == 0 {
                end_sample(&mut m)?;
                if m.run >= m.runs.len() {
                    done = true;
                    break;
                }
            }
        }
        if done {
            self.stage = Stage::Header {
                have: 0,
                buf: [0; 8],
            };
            self.next = Next::MoofOrEnd;
        } else {
            self.mdat = Some(m);
        }
        Ok(used)
    }

    /// Reports the stream once it ended where the mode says it must.
    pub(crate) fn finish(&self) -> MediaResult<Fmp4Info> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let complete = match self.mode {
            Fmp4Mode::Reader => self.stage == Stage::End,
            Fmp4Mode::Sealer => {
                self.next == Next::MoofOrEnd
                    && self.stage
                        == Stage::Header {
                            have: 0,
                            buf: [0; 8],
                        }
            }
        };
        if !complete {
            return Err(nc(
                "an fMP4 stream that ends inside a box or before its first fragment",
            ));
        }
        let moov = self
            .moov
            .as_ref()
            .ok_or_else(|| nc("an fMP4 stream without a moov"))?;
        let video_index = usize::from(!moov.video[0]);
        let units = self.decode_time.get(video_index).copied().unwrap_or(0);
        let ms = units / 90;
        let duration_ms = u32::try_from(ms).map_err(|_| nc("a video longer than VIDEO_MAX_MS"))?;
        if duration_ms == 0 || duration_ms > VIDEO_MAX_MS {
            return Err(nc("a video duration outside 1 … VIDEO_MAX_MS"));
        }
        let (width, height) = match moov.rotation {
            90 | 270 => (VIDEO_CODED_HEIGHT, VIDEO_CODED_WIDTH),
            _ => (VIDEO_CODED_WIDTH, VIDEO_CODED_HEIGHT),
        };
        Ok(Fmp4Info {
            width,
            height,
            rotation: moov.rotation,
            duration_ms,
            colour: moov.colour,
            profile_idc: moov.profile_idc,
            video_track: moov.video_track(),
            moofs: self.moofs.clone(),
        })
    }
}

/// Ends the current sample: it must end at a NAL boundary, and a video sample is a sync sample
/// exactly when it held an IDR slice. Moves to the next sample.
fn end_sample(m: &mut Mdat) -> MediaResult<()> {
    let run = m
        .runs
        .get(m.run)
        .ok_or_else(|| nc("mdat bytes beyond the trafs' samples"))?;
    if run.video {
        if m.nal != (Nal::Len { have: 0, value: 0 }) {
            return Err(nc("a video sample that ends inside a NAL unit"));
        }
        let sync = run.samples.get(m.sample).is_some_and(|s| s.1);
        if sync != m.saw_idr {
            return Err(nc("a sync flag that does not match the sample's IDR slice"));
        }
    }
    m.saw_idr = false;
    m.sample = m.sample.saturating_add(1);
    if m.sample >= run.samples.len() {
        m.sample = 0;
        m.run = m.run.saturating_add(1);
    }
    m.sample_left = m
        .runs
        .get(m.run)
        .and_then(|r| r.samples.get(m.sample))
        .map_or(0, |s| s.0);
    Ok(())
}

/// One step of the NAL state machine over `data` (bytes of the current video sample, at most the
/// bytes left in it); returns how many it used.
fn nal_step(moov: &Moov, m: &mut Mdat, data: &[u8], sample_left: u32) -> MediaResult<usize> {
    let Some(&b) = data.first() else {
        return Ok(0);
    };
    match m.nal {
        Nal::Len { have, value } => {
            let value = (value << 8) | u32::from(b);
            let have = have.saturating_add(1);
            if have < 4 {
                m.nal = Nal::Len { have, value };
            } else {
                // The four length bytes are inside the sample, so `sample_left` counts this byte.
                let after = sample_left.saturating_sub(1);
                if value == 0 || value > after {
                    return Err(nc("a NAL length of zero or beyond its sample"));
                }
                m.nal = Nal::Header { len: value };
            }
            Ok(1)
        }
        Nal::Header { len } => {
            if b & 0x80 != 0 {
                return Err(nc("a NAL unit with forbidden_zero_bit set"));
            }
            let left = len.saturating_sub(1);
            m.nal = match b & 0x1F {
                1 | 5 => {
                    if b & 0x1F == 5 {
                        m.saw_idr = true;
                    }
                    if left == 0 {
                        return Err(nc("an empty slice NAL unit"));
                    }
                    Nal::Skip { left }
                }
                6 => {
                    // `len` counts the header byte: the NAL unit, header included, is at most
                    // 1 024 bytes (the review of S1: the bound was on the payload, 1 025 in all).
                    if left == 0 || len > SEI_MAX_BYTES {
                        return Err(nc("an SEI NAL unit of 0 or more than 1 024 bytes"));
                    }
                    m.sei.clear();
                    reserve_wiped(&mut m.sei, usize::try_from(left).unwrap_or(0));
                    Nal::Sei { left }
                }
                7 | 8 => {
                    let (which, set) = if b & 0x1F == 7 {
                        (ParamSet::Sps, &moov.sps)
                    } else {
                        (ParamSet::Pps, &moov.pps)
                    };
                    if usize::try_from(len).ok() != Some(set.len()) || set.first() != Some(&b) {
                        return Err(nc("an in-band SPS or PPS other than the avcC's"));
                    }
                    if left == 0 {
                        Nal::Len { have: 0, value: 0 }
                    } else {
                        Nal::Same { which, at: 1, left }
                    }
                }
                9 => {
                    if left != 1 {
                        return Err(nc("an access unit delimiter that is not one byte"));
                    }
                    Nal::Aud
                }
                _ => return Err(nc("a NAL unit type outside 1, 5, 6, 7, 8, 9")),
            };
            Ok(1)
        }
        Nal::Skip { left } => {
            let n = usize::try_from(left).unwrap_or(usize::MAX).min(data.len());
            let left = left.saturating_sub(u32::try_from(n).unwrap_or(u32::MAX));
            m.nal = if left == 0 {
                Nal::Len { have: 0, value: 0 }
            } else {
                Nal::Skip { left }
            };
            Ok(n)
        }
        Nal::Sei { left } => {
            let n = usize::try_from(left).unwrap_or(usize::MAX).min(data.len());
            extend_wiped(&mut m.sei, data.get(..n).unwrap_or(&[]));
            let left = left.saturating_sub(u32::try_from(n).unwrap_or(u32::MAX));
            if left == 0 {
                check_sei(&m.sei)?;
                m.sei.clear();
                m.nal = Nal::Len { have: 0, value: 0 };
            } else {
                m.nal = Nal::Sei { left };
            }
            Ok(n)
        }
        Nal::Same { which, at, left } => {
            let set = match which {
                ParamSet::Sps => &moov.sps,
                ParamSet::Pps => &moov.pps,
            };
            let n = usize::try_from(left).unwrap_or(usize::MAX).min(data.len());
            let from = usize::try_from(at).unwrap_or(usize::MAX);
            let want = set.get(from..from.saturating_add(n));
            if want != data.get(..n) {
                return Err(nc("an in-band SPS or PPS other than the avcC's"));
            }
            let left = left.saturating_sub(u32::try_from(n).unwrap_or(u32::MAX));
            let at = at.saturating_add(u32::try_from(n).unwrap_or(u32::MAX));
            m.nal = if left == 0 {
                Nal::Len { have: 0, value: 0 }
            } else {
                Nal::Same { which, at, left }
            };
            Ok(n)
        }
        Nal::Aud => {
            if b & 0x1F != 0x10 {
                return Err(nc("an access unit delimiter without its stop bit"));
            }
            m.nal = Nal::Len { have: 0, value: 0 };
            Ok(1)
        }
    }
}

/// An SEI RBSP holds only buffering period (0), picture timing (1) and recovery point (6) messages
/// (§8.3 `GhostMuxer` point 3), each read to its size, then the trailing bits.
fn check_sei(payload: &[u8]) -> MediaResult<()> {
    let data = sps::rbsp(payload)?;
    let mut c = Cursor::new(&data, "a malformed SEI message");
    loop {
        let mut typ = 0u32;
        loop {
            let b = c.u8()?;
            typ = typ.saturating_add(u32::from(b));
            if b != 0xFF {
                break;
            }
        }
        let mut size = 0u32;
        loop {
            let b = c.u8()?;
            size = size.saturating_add(u32::from(b));
            if b != 0xFF {
                break;
            }
        }
        if !matches!(typ, 0 | 1 | 6) {
            return Err(nc(
                "an SEI payload type other than 0, 1 or 6 (user data is refused)",
            ));
        }
        c.take(usize::try_from(size).unwrap_or(usize::MAX))?;
        let at = c.position();
        let tail = data.get(at..).unwrap_or(&[]);
        if tail == [0x80] {
            return Ok(());
        }
        if tail.is_empty() {
            return Err(nc("an SEI RBSP without its trailing bits"));
        }
    }
}
