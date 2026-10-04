//! The magic-byte sniffer of a picked source (design §6.1, §9.1, §9.2, §13.2 M10; S0-4, S0-21):
//! the main process reads the first 64 bytes and refuses anything outside the allowlist before the
//! sandbox or Media3 sees a byte.
//!
//! Accepted: JPEG; PNG (signature and an `IHDR` first chunk); static WebP (`VP8 `, `VP8L`, or `VP8X`
//! without the animation flag); an ISO-BMFF file whose `ftyp` box lies inside the 64 bytes and names
//! none of the [`IMAGE_BRANDS`] among its major and compatible brands. Refused (`UNSUPPORTED`):
//! HEIC/HEIF/AVIF (no sandbox decoder reaches them, S0-4), GIF, animated WebP, DNG and other
//! TIFF-based RAW, BMP, ICO, WBMP, SVG and anything else, including an `ftyp` the 64 bytes do not
//! hold whole.
//!
//! **What the brand list is, and is not.** It is the HEIF structural, image, sequence and profile
//! brands S1 knows (ISO/IEC 23008-12 with its HEVC, AVC, JPEG, VVC, EVC and JPEG 2000 bindings;
//! MIAF, ISO/IEC 23000-22; the AV1 image file format), 32 of them; it is not every brand any
//! specification will ever define. An image file whose `ftyp` names only brands outside the list
//! is classified as video here (the review of S1 found `jpeg`, `avci`, `avcs`, `vvic`, `j2ki`, `MiHB`
//! and `MA1B` missing from S1's first list of 16), and Media3's `Mp4Extractor`, the only extractor
//! a picked source reaches, then refuses it (S0-21 measured HEIF and AVIF failing there): the list
//! decides which refusal the user sees, not whether an image reaches a decoder. That a "video" is
//! really one is `Mp4Extractor`'s to establish (S0-21); a static/animated PNG cannot be told apart in
//! 64 bytes (`acTL` may follow later chunks), and the sandbox's re-encode keeps one frame either way.

use crate::consts::SNIFF_BYTES;
use crate::error::{Code, MediaError, MediaResult};

/// The source types of the allowlist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceType {
    /// A JPEG file (re-encoded in the sandbox).
    Jpeg,
    /// A PNG file.
    Png,
    /// A static WebP file.
    Webp,
    /// An ISO-BMFF video container (MP4, 3GP, QuickTime) for Media3's `Mp4Extractor`.
    IsoBmffVideo,
}

/// The HEIF, MIAF and AVIF brands that mark an image or image-sequence file (ISO/IEC 23008-12 and
/// its codec bindings, 23000-22; the AV1 image file format). A video container carries none.
pub const IMAGE_BRANDS: [&[u8; 4]; 32] = [
    // HEIF structural brands, and MIAF's.
    b"mif1", b"mif2", b"mif3", b"msf1", b"miaf", b"1pic",
    // HEVC images and sequences.
    b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx", b"hevm", b"hevs",
    // AVC, JPEG, VVC, EVC and JPEG 2000 images and sequences.
    b"avci", b"avcs", b"jpeg", b"jpgs", b"vvic", b"vvis", b"evbi", b"evbs", b"j2ki", b"j2is",
    // AVIF, and the MIAF and AVIF profile brands.
    b"avif", b"avis", b"avio", b"MA1A", b"MA1B", b"MiHA", b"MiHB", b"MiHE",
];

fn unsupported(rule: &'static str) -> MediaError {
    MediaError::new(Code::Unsupported, rule)
}

/// `sniff(first64)`: the type of a source from its first bytes (at most 64 are read).
pub fn sniff(first: &[u8]) -> MediaResult<SourceType> {
    let head = first.get(..first.len().min(SNIFF_BYTES)).unwrap_or(&[]);
    if head.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Ok(SourceType::Jpeg);
    }
    if head.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        // The first chunk is IHDR, 13 bytes long.
        return if head.get(8..16) == Some(&[0, 0, 0, 13, b'I', b'H', b'D', b'R'][..]) {
            Ok(SourceType::Png)
        } else {
            Err(unsupported("a PNG whose first chunk is not IHDR"))
        };
    }
    if head.get(0..4) == Some(b"RIFF") && head.get(8..12) == Some(b"WEBP") {
        return match head.get(12..16) {
            Some(b"VP8 ") | Some(b"VP8L") => Ok(SourceType::Webp),
            Some(b"VP8X") => match head.get(20) {
                // VP8X flags: bit 1 is the animation flag.
                Some(flags) if flags & 0x02 == 0 => Ok(SourceType::Webp),
                Some(_) => Err(unsupported("an animated WebP")),
                None => Err(unsupported("a WebP whose VP8X header is cut")),
            },
            _ => Err(unsupported("a WebP of an unknown chunk")),
        };
    }
    if head.get(4..8) == Some(b"ftyp") {
        let size = crate::bytes::be_u32(head, 0).unwrap_or(0);
        let size = usize::try_from(size).unwrap_or(usize::MAX);
        if size < 16 || size > head.len() || size % 4 != 0 {
            return Err(unsupported("an ftyp the first 64 bytes do not hold whole"));
        }
        let major = head.get(8..12);
        let compatible = head.get(16..size).unwrap_or(&[]);
        let mut brands = compatible.chunks(4).chain(major);
        if brands.any(|b| IMAGE_BRANDS.iter().any(|i| &i[..] == b)) {
            return Err(unsupported("a HEIF or AVIF image brand (S0-4)"));
        }
        return Ok(SourceType::IsoBmffVideo);
    }
    Err(unsupported(
        "a source outside JPEG, PNG, static WebP and ISO-BMFF video",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ftyp(major: &[u8; 4], compat: &[&[u8; 4]]) -> Vec<u8> {
        let size = 16 + 4 * compat.len();
        let mut v = (size as u32).to_be_bytes().to_vec();
        v.extend_from_slice(b"ftyp");
        v.extend_from_slice(major);
        v.extend_from_slice(&[0, 0, 2, 0]);
        for c in compat {
            v.extend_from_slice(*c);
        }
        v.extend_from_slice(&[0, 0, 0, 8, b'f', b'r', b'e', b'e']);
        v
    }

    /// Every image brand, written out apart from [`IMAGE_BRANDS`] so that a brand dropped from the
    /// list fails here (the review of S1: nine of the first sixteen were in no test).
    const EVERY_IMAGE_BRAND: [&str; 32] = [
        "mif1", "mif2", "mif3", "msf1", "miaf", "1pic", "heic", "heix", "heim", "heis", "hevc",
        "hevx", "hevm", "hevs", "avci", "avcs", "jpeg", "jpgs", "vvic", "vvis", "evbi", "evbs",
        "j2ki", "j2is", "avif", "avis", "avio", "MA1A", "MA1B", "MiHA", "MiHB", "MiHE",
    ];

    #[test]
    fn every_image_brand_is_refused_as_major_and_as_compatible() {
        assert_eq!(IMAGE_BRANDS.len(), EVERY_IMAGE_BRAND.len());
        for b in EVERY_IMAGE_BRAND {
            let brand: &[u8; 4] = b.as_bytes().try_into().expect("four bytes");
            assert_eq!(
                sniff(&ftyp(brand, &[b"isom"])).map_err(|e| e.code()),
                Err(Code::Unsupported),
                "major {b}"
            );
            assert_eq!(
                sniff(&ftyp(b"isom", &[b"iso2", brand])).map_err(|e| e.code()),
                Err(Code::Unsupported),
                "compatible {b}"
            );
        }
    }

    #[test]
    fn the_allowlist() {
        assert_eq!(sniff(&[0xFF, 0xD8, 0xFF, 0xE0]), Ok(SourceType::Jpeg));
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend_from_slice(&[0, 0, 0, 13, b'I', b'H', b'D', b'R']);
        assert_eq!(sniff(&png), Ok(SourceType::Png));
        let mut webp = b"RIFF\x10\x00\x00\x00WEBPVP8 ".to_vec();
        assert_eq!(sniff(&webp), Ok(SourceType::Webp));
        webp.truncate(12);
        webp.extend_from_slice(b"VP8X\x0a\x00\x00\x00\x02\x00\x00\x00");
        assert_eq!(sniff(&webp).map_err(|e| e.code()), Err(Code::Unsupported));
        assert_eq!(
            sniff(&ftyp(b"isom", &[b"isom", b"iso2", b"avc1", b"mp41"])),
            Ok(SourceType::IsoBmffVideo)
        );
        assert_eq!(
            sniff(&ftyp(b"qt  ", &[b"qt  "])),
            Ok(SourceType::IsoBmffVideo)
        );
        for bad in [
            ftyp(b"heic", &[b"mif1", b"heic"]),
            ftyp(b"mp41", &[b"avif"]),
            ftyp(b"msf1", &[]),
        ] {
            assert_eq!(sniff(&bad).map_err(|e| e.code()), Err(Code::Unsupported));
        }
        for bad in [
            &b"GIF89a"[..],
            b"BM\x00\x00",
            b"II*\x00",
            b"MM\x00*",
            b"<svg",
            b"\x00\x00\x01\x00",
            b"\x1aE\xdf\xa3",
            b"",
        ] {
            assert_eq!(
                sniff(bad).map_err(|e| e.code()),
                Err(Code::Unsupported),
                "{bad:?}"
            );
        }
    }
}
