//! The content walker the sealer and the reader run over an object's plaintext (D16): the JPEG
//! profile for an image, the fMP4 profile for a video. What it reports is what the manifest must
//! state (§3.5: the sealer derives `width`, `height` and `duration_ms` from the walk, the reader
//! recomputes them).

use crate::consts::MediaKind;
use crate::error::MediaResult;
use crate::fmp4::{Fmp4Info, Fmp4Mode, Fmp4Walker};
use crate::geometry;
use crate::jpeg::{JpegMode, JpegWalker};

/// What a complete walk reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WalkedContent {
    pub(crate) width: u16,
    pub(crate) height: u16,
    pub(crate) duration_ms: u32,
    /// The video's walk (the sealer builds the `mfra` from it).
    pub(crate) video: Option<Fmp4Info>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ContentWalker {
    Image(JpegWalker),
    Video(Fmp4Walker),
}

impl ContentWalker {
    /// The sealer's walker: a video stream ends before the `mfra` the sealer appends.
    pub(crate) fn for_sealer(kind: MediaKind) -> Self {
        match kind {
            MediaKind::Image => ContentWalker::Image(JpegWalker::new(JpegMode::Check)),
            MediaKind::Video => ContentWalker::Video(Fmp4Walker::new(Fmp4Mode::Sealer)),
        }
    }

    /// The reader's walker: a video's content ends with GHOST's `mfra`.
    pub(crate) fn for_reader(kind: MediaKind) -> Self {
        match kind {
            MediaKind::Image => ContentWalker::Image(JpegWalker::new(JpegMode::Check)),
            MediaKind::Video => ContentWalker::Video(Fmp4Walker::new(Fmp4Mode::Reader)),
        }
    }

    pub(crate) fn feed(&mut self, data: &[u8]) -> MediaResult<()> {
        match self {
            ContentWalker::Image(w) => w.feed(data, None),
            ContentWalker::Video(w) => w.feed(data),
        }
    }

    /// The walk's result, with the canonical geometry of D29 checked.
    pub(crate) fn finish(&self) -> MediaResult<WalkedContent> {
        match self {
            ContentWalker::Image(w) => {
                let info = w.finish()?;
                geometry::check_image(info.width, info.height)?;
                Ok(WalkedContent {
                    width: info.width,
                    height: info.height,
                    duration_ms: 0,
                    video: None,
                })
            }
            ContentWalker::Video(w) => {
                let info = w.finish()?;
                geometry::check_video(info.width, info.height)?;
                Ok(WalkedContent {
                    width: info.width,
                    height: info.height,
                    duration_ms: info.duration_ms,
                    video: Some(info),
                })
            }
        }
    }
}
