//! The H.264 sequence parameter set of the canonical fMP4 profile (design §8.3, S0-22): profile 66
//! (Baseline) or 100 (High: `chroma_format_idc` 1, 8-bit), `level_idc` 31, `frame_mbs_only_flag` 1,
//! the coded size 1 280 × 720, walked **in full** (scaling lists included, ITU-T H.264 §7.3.2.1.1
//! and §7.3.2.1.1.1) to its VUI (Annex E.1.1), whose colour description is absent or exactly the
//! `colr` box's values, with `video_full_range_flag` 0, and which ends exactly at the RBSP trailing
//! bits. Every read is checked; Exp-Golomb codes longer than 32 bits are refused.

use crate::consts::{VIDEO_CODED_HEIGHT, VIDEO_CODED_WIDTH};
use crate::error::{MediaError, MediaResult};

/// What the walk reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SpsInfo {
    pub(crate) profile_idc: u8,
    pub(crate) level_idc: u8,
    /// The VUI colour description `(primaries, transfer, matrix)`, if present.
    pub(crate) colour: Option<(u8, u8, u8)>,
}

fn nc(rule: &'static str) -> MediaError {
    MediaError::non_canonical(rule)
}

/// The RBSP of a NAL unit's payload (after its one-byte header): every `00 00 03` loses its `03`,
/// and a `00 00` followed by `00`, `01` or `02` is refused (H.264 §7.4.1).
pub(crate) fn rbsp(payload: &[u8]) -> MediaResult<Vec<u8>> {
    let mut out = Vec::with_capacity(payload.len());
    let mut zeros = 0usize;
    for &b in payload {
        if zeros >= 2 {
            if b == 0x03 {
                zeros = 0;
                continue;
            }
            if b <= 0x02 {
                return Err(nc("a start-code prefix inside a NAL unit"));
            }
        }
        if b == 0 {
            zeros = zeros.saturating_add(1);
        } else {
            zeros = 0;
        }
        out.push(b);
    }
    Ok(out)
}

/// An MSB-first bit reader over an RBSP.
pub(crate) struct Bits<'a> {
    data: &'a [u8],
    bit: usize,
}

impl<'a> Bits<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Bits { data, bit: 0 }
    }

    pub(crate) fn u1(&mut self) -> MediaResult<u32> {
        let byte = self
            .data
            .get(self.bit / 8)
            .ok_or_else(|| nc("an SPS that ends early"))?;
        let shift = 7usize.saturating_sub(self.bit % 8);
        self.bit = self.bit.saturating_add(1);
        Ok(u32::from((byte >> shift) & 1))
    }

    pub(crate) fn u(&mut self, n: u32) -> MediaResult<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | self.u1()?;
        }
        Ok(v)
    }

    /// `ue(v)`, refusing codes of more than 31 leading zeros.
    pub(crate) fn ue(&mut self) -> MediaResult<u32> {
        let mut zeros = 0u32;
        while self.u1()? == 0 {
            zeros = zeros.saturating_add(1);
            if zeros > 31 {
                return Err(nc("an Exp-Golomb code longer than 32 bits"));
            }
        }
        let rest = self.u(zeros)?;
        let base = (1u64 << zeros).saturating_sub(1);
        u32::try_from(base.saturating_add(u64::from(rest)))
            .map_err(|_| nc("an Exp-Golomb value above 2^32 - 2"))
    }

    /// `se(v)`.
    pub(crate) fn se(&mut self) -> MediaResult<i64> {
        let k = i64::from(self.ue()?);
        Ok(if k % 2 == 1 {
            k.saturating_add(1) / 2
        } else {
            0i64.saturating_sub(k / 2)
        })
    }

    /// Refuses unless the next bits are exactly the RBSP trailing bits: a 1, zeros to the byte
    /// boundary, and no byte after it.
    pub(crate) fn trailing(&mut self) -> MediaResult<()> {
        if self.u1()? != 1 {
            return Err(nc("an RBSP without its stop bit"));
        }
        while !self.bit.is_multiple_of(8) {
            if self.u1()? != 0 {
                return Err(nc("RBSP trailing bits that are not zero"));
            }
        }
        if self.bit / 8 != self.data.len() {
            return Err(nc("bytes after the RBSP trailing bits"));
        }
        Ok(())
    }
}

fn bounded(v: u32, max: u32, rule: &'static str) -> MediaResult<u32> {
    if v > max {
        Err(nc(rule))
    } else {
        Ok(v)
    }
}

fn scaling_list(b: &mut Bits<'_>, size: u32) -> MediaResult<()> {
    let mut last: i64 = 8;
    let mut next: i64 = 8;
    for _ in 0..size {
        if next != 0 {
            let delta = b.se()?;
            if !(-128..=127).contains(&delta) {
                return Err(nc("a scaling-list delta outside -128 … 127"));
            }
            next = (last.saturating_add(delta).saturating_add(256)).rem_euclid(256);
        }
        if next != 0 {
            last = next;
        }
    }
    Ok(())
}

fn hrd(b: &mut Bits<'_>) -> MediaResult<()> {
    let cpb_cnt = bounded(b.ue()?, 31, "cpb_cnt_minus1 above 31")?;
    b.u(4)?; // bit_rate_scale
    b.u(4)?; // cpb_size_scale
    for _ in 0..=cpb_cnt {
        b.ue()?; // bit_rate_value_minus1
        b.ue()?; // cpb_size_value_minus1
        b.u1()?; // cbr_flag
    }
    b.u(5)?; // initial_cpb_removal_delay_length_minus1
    b.u(5)?; // cpb_removal_delay_length_minus1
    b.u(5)?; // dpb_output_delay_length_minus1
    b.u(5)?; // time_offset_length
    Ok(())
}

fn vui(b: &mut Bits<'_>) -> MediaResult<Option<(u8, u8, u8)>> {
    let mut colour = None;
    if b.u1()? == 1 {
        // aspect_ratio_info: square pixels only, like the `pasp` box (65 536 : 65 536).
        let idc = b.u(8)?;
        if idc == 255 {
            let (w, h) = (b.u(16)?, b.u(16)?);
            if w == 0 || w != h {
                return Err(nc("an SPS sample aspect ratio that is not square"));
            }
        } else if idc > 1 {
            return Err(nc("an SPS sample aspect ratio that is not square"));
        }
    }
    if b.u1()? == 1 {
        b.u1()?; // overscan_appropriate_flag
    }
    if b.u1()? == 1 {
        b.u(3)?; // video_format
        if b.u1()? != 0 {
            return Err(nc("video_full_range_flag 1 (the profile is limited range)"));
        }
        if b.u1()? == 1 {
            let p = u8::try_from(b.u(8)?).unwrap_or(0);
            let t = u8::try_from(b.u(8)?).unwrap_or(0);
            let m = u8::try_from(b.u(8)?).unwrap_or(0);
            colour = Some((p, t, m));
        }
    }
    if b.u1()? == 1 {
        bounded(b.ue()?, 5, "chroma_sample_loc_type above 5")?;
        bounded(b.ue()?, 5, "chroma_sample_loc_type above 5")?;
    }
    if b.u1()? == 1 {
        b.u(32)?; // num_units_in_tick
        b.u(32)?; // time_scale
        b.u1()?; // fixed_frame_rate_flag
    }
    let nal_hrd = b.u1()?;
    if nal_hrd == 1 {
        hrd(b)?;
    }
    let vcl_hrd = b.u1()?;
    if vcl_hrd == 1 {
        hrd(b)?;
    }
    if nal_hrd == 1 || vcl_hrd == 1 {
        b.u1()?; // low_delay_hrd_flag
    }
    b.u1()?; // pic_struct_present_flag
    if b.u1()? == 1 {
        b.u1()?; // motion_vectors_over_pic_boundaries_flag
        b.ue()?; // max_bytes_per_pic_denom
        b.ue()?; // max_bits_per_mb_denom
        b.ue()?; // log2_max_mv_length_horizontal
        b.ue()?; // log2_max_mv_length_vertical
        b.ue()?; // max_num_reorder_frames
        b.ue()?; // max_dec_frame_buffering
    }
    Ok(colour)
}

/// Walks an SPS NAL unit (header byte included) in full.
pub(crate) fn walk(nal: &[u8]) -> MediaResult<SpsInfo> {
    let (&header, payload) = nal.split_first().ok_or_else(|| nc("an empty SPS"))?;
    if header & 0x80 != 0 || header & 0x1F != 7 || header & 0x60 == 0 {
        return Err(nc(
            "an SPS NAL header that is not a reference NAL of type 7",
        ));
    }
    let data = rbsp(payload)?;
    let mut b = Bits::new(&data);
    let profile_idc = u8::try_from(b.u(8)?).unwrap_or(0);
    b.u(8)?; // constraint_set flags and reserved_zero_2bits
    let level_idc = u8::try_from(b.u(8)?).unwrap_or(0);
    if profile_idc != 66 && profile_idc != 100 {
        return Err(nc("an SPS profile other than 66 (Baseline) or 100 (High)"));
    }
    if level_idc != 31 {
        return Err(nc("an SPS level_idc other than 31"));
    }
    bounded(b.ue()?, 31, "seq_parameter_set_id above 31")?;
    if profile_idc == 100 {
        if b.ue()? != 1 {
            return Err(nc(
                "a High-profile SPS whose chroma_format_idc is not 1 (4:2:0)",
            ));
        }
        if b.ue()? != 0 || b.ue()? != 0 {
            return Err(nc("a High-profile SPS that is not 8-bit"));
        }
        if b.u1()? != 0 {
            return Err(nc("qpprime_y_zero_transform_bypass_flag 1"));
        }
        if b.u1()? == 1 {
            // seq_scaling_matrix_present_flag: eight lists for chroma_format_idc 1.
            for i in 0..8u32 {
                if b.u1()? == 1 {
                    scaling_list(&mut b, if i < 6 { 16 } else { 64 })?;
                }
            }
        }
    }
    bounded(b.ue()?, 12, "log2_max_frame_num_minus4 above 12")?;
    match b.ue()? {
        0 => {
            bounded(b.ue()?, 12, "log2_max_pic_order_cnt_lsb_minus4 above 12")?;
        }
        1 => {
            b.u1()?; // delta_pic_order_always_zero_flag
            b.se()?; // offset_for_non_ref_pic
            b.se()?; // offset_for_top_to_bottom_field
            let cycle = bounded(
                b.ue()?,
                255,
                "num_ref_frames_in_pic_order_cnt_cycle above 255",
            )?;
            for _ in 0..cycle {
                b.se()?;
            }
        }
        2 => {}
        _ => return Err(nc("pic_order_cnt_type above 2")),
    }
    bounded(b.ue()?, 16, "max_num_ref_frames above 16")?;
    b.u1()?; // gaps_in_frame_num_value_allowed_flag
    let width_mbs = u64::from(b.ue()?).saturating_add(1);
    let height_units = u64::from(b.ue()?).saturating_add(1);
    if b.u1()? != 1 {
        return Err(nc("frame_mbs_only_flag 0 (interlaced coding)"));
    }
    b.u1()?; // direct_8x8_inference_flag
    let (mut crop_x, mut crop_y) = (0u64, 0u64);
    if b.u1()? == 1 {
        // 4:2:0 frame coding: crop units of 2 × 2 samples.
        let (l, r, t, bt) = (b.ue()?, b.ue()?, b.ue()?, b.ue()?);
        crop_x = (u64::from(l).saturating_add(u64::from(r))).saturating_mul(2);
        crop_y = (u64::from(t).saturating_add(u64::from(bt))).saturating_mul(2);
    }
    let width = width_mbs.saturating_mul(16).saturating_sub(crop_x);
    let height = height_units.saturating_mul(16).saturating_sub(crop_y);
    if width != u64::from(VIDEO_CODED_WIDTH) || height != u64::from(VIDEO_CODED_HEIGHT) {
        return Err(nc("an SPS coded size other than 1 280 × 720"));
    }
    let colour = if b.u1()? == 1 { vui(&mut b)? } else { None };
    b.trailing()?;
    Ok(SpsInfo {
        profile_idc,
        level_idc,
        colour,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An MSB-first bit writer with Exp-Golomb codes, for building SPS fixtures.
    #[derive(Default)]
    pub(crate) struct BitWriter {
        bytes: Vec<u8>,
        bits: usize,
    }

    impl BitWriter {
        pub(crate) fn u(&mut self, n: u32, v: u64) -> &mut Self {
            for i in (0..n).rev() {
                if self.bits.is_multiple_of(8) {
                    self.bytes.push(0);
                }
                let bit = ((v >> i) & 1) as u8;
                let last = self.bytes.last_mut().expect("pushed");
                *last |= bit << (7 - self.bits % 8);
                self.bits += 1;
            }
            self
        }
        pub(crate) fn ue(&mut self, v: u64) -> &mut Self {
            let x = v + 1;
            let len = 64 - x.leading_zeros();
            self.u(len - 1, 0).u(len, x)
        }
        pub(crate) fn se(&mut self, v: i64) -> &mut Self {
            let k = if v > 0 { 2 * v - 1 } else { -2 * v };
            self.ue(k as u64)
        }
        pub(crate) fn trailing(&mut self) -> Vec<u8> {
            self.u(1, 1);
            while !self.bits.is_multiple_of(8) {
                self.u(1, 0);
            }
            // Emulation prevention.
            let mut out = Vec::new();
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

    /// The API 29 emulator golden's SPS (no VUI) and the API 35 one's (with a VUI).
    pub(crate) const SPS_API29: &str = "6742c01f8d6805005ba01e1108d4";
    pub(crate) const SPS_API35: &str = "6742c01f8d6805005ba420a020c0f08846a0";

    #[test]
    fn walks_both_golden_sps() {
        let a = walk(&hex::decode(SPS_API29).expect("hex")).expect("api29");
        assert_eq!((a.profile_idc, a.level_idc), (66, 31));
        let b = walk(&hex::decode(SPS_API35).expect("hex")).expect("api35");
        assert_eq!(b.colour, Some((5, 1, 6)));
    }

    /// A High-profile SPS of 1 280 × 720 with every scaling list present and a VUI colour.
    pub(crate) fn high_sps(
        chroma: u64,
        bit_depth: u64,
        full_range: u64,
        colour: (u64, u64, u64),
    ) -> Vec<u8> {
        let mut w = BitWriter::default();
        w.u(8, 100).u(8, 0).u(8, 31).ue(0);
        w.ue(chroma).ue(bit_depth).ue(bit_depth).u(1, 0).u(1, 1);
        for i in 0..8 {
            w.u(1, 1);
            let size = if i < 6 { 16 } else { 64 };
            for j in 0..size {
                w.se(if j % 3 == 0 { 2 } else { -1 });
            }
        }
        w.ue(0)
            .ue(0)
            .ue(0)
            .ue(4)
            .u(1, 0)
            .ue(79)
            .ue(44)
            .u(1, 1)
            .u(1, 1)
            .u(1, 0);
        w.u(1, 1); // vui_parameters_present_flag
        w.u(1, 1).u(8, 1); // aspect 1:1
        w.u(1, 0); // overscan
        w.u(1, 1)
            .u(3, 5)
            .u(1, full_range)
            .u(1, 1)
            .u(8, colour.0)
            .u(8, colour.1)
            .u(8, colour.2);
        w.u(1, 0); // chroma loc
        w.u(1, 1).u(32, 1).u(32, 60).u(1, 0); // timing
        w.u(1, 0).u(1, 0); // no HRD
        w.u(1, 0); // pic_struct
        w.u(1, 1).u(1, 1).ue(0).ue(0).ue(16).ue(16).ue(0).ue(4);
        let mut nal = vec![0x67];
        nal.extend(w.trailing());
        nal
    }

    #[test]
    fn walks_a_high_profile_sps_with_scaling_lists() {
        let s = walk(&high_sps(1, 0, 0, (1, 1, 1))).expect("High 4:2:0 8-bit");
        assert_eq!((s.profile_idc, s.colour), (100, Some((1, 1, 1))));
        assert!(walk(&high_sps(3, 0, 0, (1, 1, 1))).is_err(), "4:4:4");
        assert!(walk(&high_sps(1, 2, 0, (1, 1, 1))).is_err(), "10-bit");
        assert!(walk(&high_sps(1, 0, 1, (1, 1, 1))).is_err(), "full range");
        let mut extra = high_sps(1, 0, 0, (1, 1, 1));
        extra.push(0x80);
        assert!(walk(&extra).is_err(), "a byte after the trailing bits");
    }
}
