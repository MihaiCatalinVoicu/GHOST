//! The canonical geometry of D29 (§3.5, §8.2, §8.3; S0-20): what the walkers report to the sealer
//! and the reader, and what the manifest must state; and the ladder itself (Q37), the target size
//! `STRIP_IMAGE` scales a source to (§8.2, §6.2), so the re-encoder and the checks agree.

use crate::consts::{
    EDGE_STEP, IMAGE_LONG_EDGES, PREVIEW_LONG_EDGE, VIDEO_CODED_HEIGHT, VIDEO_CODED_WIDTH,
};
use crate::error::{MediaError, MediaResult};

fn short_edge_ok(short: u16, long: u16) -> bool {
    short >= EDGE_STEP && short <= long && short.is_multiple_of(EDGE_STEP)
}

/// `max(16, 16 · round(long · short_src / long_src / 16))`, rounding half up, at most `long`.
fn short_edge(long: u16, src_long: u32, src_short: u32) -> u16 {
    let num = u64::from(long)
        .saturating_mul(u64::from(src_short))
        .saturating_mul(2)
        .saturating_add(u64::from(src_long).saturating_mul(16));
    let den = u64::from(src_long).saturating_mul(32);
    let steps = num.checked_div(den).unwrap_or(0);
    let edge = steps.saturating_mul(u64::from(EDGE_STEP));
    u16::try_from(edge)
        .unwrap_or(u16::MAX)
        .max(EDGE_STEP)
        .min(long)
}

fn oriented(long: u16, short: u16, src_w: u32, src_h: u32) -> (u16, u16) {
    if src_w >= src_h {
        (long, short)
    } else {
        (short, long)
    }
}

/// The ladder of D29 and §8.2 (Q37): the size `STRIP_IMAGE` re-encodes a source of `src_w × src_h`
/// (after orientation) to, before any step down the ladder for size. The long edge is the largest
/// of 512, 1 024 and 2 048 not above the source's (512 for a smaller source); the short edge is
/// `max(16, 16 · round(long · ratio / 16))`, rounding half up. `None` for an empty source.
pub fn image_target(src_w: u32, src_h: u32) -> Option<(u16, u16)> {
    if src_w == 0 || src_h == 0 {
        return None;
    }
    let (src_long, src_short) = (src_w.max(src_h), src_w.min(src_h));
    let long = IMAGE_LONG_EDGES
        .iter()
        .copied()
        .rev()
        .find(|l| u32::from(*l) <= src_long)
        .unwrap_or(IMAGE_LONG_EDGES[0]);
    let short = short_edge(long, src_long, src_short);
    Some(oriented(long, short, src_w, src_h))
}

/// The preview size of a picture of `w × h`: long edge 320, the short edge as for an image.
pub fn preview_target(w: u32, h: u32) -> Option<(u16, u16)> {
    if w == 0 || h == 0 {
        return None;
    }
    let (src_long, src_short) = (w.max(h), w.min(h));
    let short = short_edge(PREVIEW_LONG_EDGE, src_long, src_short);
    Some(oriented(PREVIEW_LONG_EDGE, short, w, h))
}

/// An image object: long edge 512, 1 024 or 2 048; short edge a multiple of 16 in 16 … long.
pub(crate) fn check_image(width: u16, height: u16) -> MediaResult<()> {
    let (long, short) = (width.max(height), width.min(height));
    if IMAGE_LONG_EDGES.contains(&long) && short_edge_ok(short, long) {
        Ok(())
    } else {
        Err(MediaError::non_canonical(
            "an image's long edge is 512, 1 024 or 2 048 and its short edge a multiple of 16 (D29)",
        ))
    }
}

/// A preview: long edge 320; short edge a multiple of 16 in 16 … 320.
pub(crate) fn check_preview(width: u16, height: u16) -> MediaResult<()> {
    let (long, short) = (width.max(height), width.min(height));
    if long == PREVIEW_LONG_EDGE && short_edge_ok(short, long) {
        Ok(())
    } else {
        Err(MediaError::non_canonical(
            "a preview's long edge is 320 and its short edge a multiple of 16 (D29)",
        ))
    }
}

/// A video's displayed geometry: 1 280 × 720 or 720 × 1 280.
pub(crate) fn check_video(width: u16, height: u16) -> MediaResult<()> {
    if (width, height) == (VIDEO_CODED_WIDTH, VIDEO_CODED_HEIGHT)
        || (width, height) == (VIDEO_CODED_HEIGHT, VIDEO_CODED_WIDTH)
    {
        Ok(())
    } else {
        Err(MediaError::non_canonical(
            "a video is displayed 1 280 × 720 or 720 × 1 280 (D29, S0-20)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ladder() {
        assert!(check_image(512, 336).is_ok());
        assert!(check_image(336, 512).is_ok());
        assert!(check_image(2048, 2048).is_ok());
        assert!(check_image(1024, 16).is_ok());
        assert!(check_image(1000, 512).is_err());
        assert!(check_image(512, 330).is_err());
        assert!(check_image(512, 0).is_err());
        assert!(check_image(4096, 2048).is_err());
        assert!(check_preview(320, 208).is_ok());
        assert!(check_preview(176, 320).is_ok());
        assert!(check_preview(320, 180).is_err());
        assert!(check_preview(512, 320).is_err());
        assert!(check_video(1280, 720).is_ok());
        assert!(check_video(720, 1280).is_ok());
        assert!(check_video(1280, 1280).is_err());
    }

    #[test]
    fn the_ladder_targets_pass_the_checks() {
        assert_eq!(image_target(4032, 3024), Some((2048, 1536)));
        assert_eq!(image_target(3024, 4032), Some((1536, 2048)));
        assert_eq!(image_target(1080, 2400), Some((928, 2048)));
        assert_eq!(image_target(600, 400), Some((512, 336)));
        assert_eq!(image_target(100, 50), Some((512, 256)));
        assert_eq!(image_target(10_000, 10_000), Some((2048, 2048)));
        assert_eq!(image_target(5000, 10), Some((2048, 16)));
        assert_eq!(image_target(0, 10), None);
        assert_eq!(preview_target(2048, 1536), Some((320, 240)));
        assert_eq!(preview_target(720, 1280), Some((176, 320)));
        assert_eq!(preview_target(1280, 720), Some((320, 176)));
        for w in (1..5000).step_by(37) {
            for h in (1..5000).step_by(41) {
                let (iw, ih) = image_target(w, h).expect("image");
                check_image(iw, ih).expect("canonical image geometry");
                let (pw, ph) = preview_target(u32::from(iw), u32::from(ih)).expect("preview");
                check_preview(pw, ph).expect("canonical preview geometry");
                // Orientation kept (a nearly square source may round to a square).
                assert!(
                    if w >= h { iw >= ih } else { iw <= ih },
                    "{w}x{h} -> {iw}x{ih}"
                );
            }
        }
    }
}
