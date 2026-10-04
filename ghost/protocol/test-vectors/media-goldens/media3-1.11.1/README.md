# Media goldens, Media3 1.11.1 (emulator encoders only)

Test data for the canonical formats of `docs/design/faza11-media.md` §8.2 and §8.3 (the canonical
JPEG and fMP4 profiles, gate G-M8): every file here must be accepted by `ghost-client-media`'s
walkers, byte for byte, and the walkers' tests read them from this directory (slice S1). They were
recorded in slice S0 on 2026-10-04 by the evidence spike `ghost/spikes/media-s0` (evidence tooling,
not product code; `docs/design/faza11-s0-evidence.md` §3, §17, §24 and Appendix W) and are
**emulator goldens only**: the two encoders that made them are AOSP's Baseline-only software
encoders. Goldens of the reference phones' hardware encoders (High profile, S0-22) are added by
slice S0b before video is enabled on any device (S0-3).

## How the fMP4 files were made

The spike's `Transcoder.Mode.FINAL`, i.e. the configuration of design §8.3 with every S0
correction: forced encoding of both tracks; H.264 at 2 000 000 bit/s, VBR,
`setEncodingProfileLevel(AVCProfileBaseline, AVCLevel31)`, `setMaxBFrames(0)`,
`setiFrameIntervalSeconds(1)`, the encoder given the output's frame rate (at most 30) and SDR
**BT.601 limited range** (S0-13 as revised: both emulator encoders code BT.601 as labelled, written
as `colr` (5, 1, 6); a BT.709 request is coded as BT.709 on API 35 but as BT.601 on API 29, so the
design requests BT.601 and verifies it per encoder; its walker also accepts the BT.709 label
(1, 1, 1) for an encoder that codes BT.709, of which there is no golden yet); AAC-LC 128 kbit/s, 48 kHz stereo (Sonic resampler, explicit down-mix
matrices); `Presentation` 1 280 × 720 or 720 × 1 280 (scale to fit), `FrameDropEffect(30)`;
the sequence's forced silent audio track; sources through `ContentDataSource` and `Mp4Extractor`
only; GHOST's muxer wrapper over `FragmentedMp4Muxer` (no metadata but a constant timestamp, the
rotation of the video track as `Mp4OrientationData`, SEI filter). Each file is that muxer's output
**after** the two steps the sealing channel adds (S0-2): a version-1 `tfdt` inserted into every
`traf`, and GHOST's `mfra` appended (one `tfra` entry per `moof`, then `mfro`).

| Directory | Emulator image | Encoders |
|---|---|---|
| `api35-emulator/` | `sdk_phone64_x86_64` 15 `AE3A.240806.019` (AVD `ghost-dm-api35`) | `c2.android.avc.encoder`, `c2.android.aac.encoder` |
| `api29-emulator/` | `sdk_phone_x86_64` 10 `QSR1.210820.001` (AVD `ghost-dm-api29`, booted with `-feature GLESDynamicVersion`) | `OMX.google.h264.encoder`, `OMX.google.aac.encoder` |

| File | Source (made on the API 35 emulator, identical input on both levels) | What it pins |
|---|---|---|
| `quad_land.fmp4` | 1 280 × 720, 30 fps, 4 s, a 3 × 2 grid of saturated colours, BT.601 full range | rotation 0, the colours coded BT.601 limited and labelled so (every patch within 2–3 levels when decoded as labelled) |
| `quad_rot90.fmp4` | the same grid stored landscape with a 90° rotation (how phones store portrait video) | coded 1 280 × 720 with a 90° matrix in both `tkhd` |
| `quad_rot180.fmp4` | rotation 180 | a 180° matrix (the source's rotation passes through, S0-20) |
| `quad_rot270.fmp4` | rotation 270 | a 270° matrix |
| `quad_port.fmp4` | the grid coded 720 × 1 280, rotation 0 | coded 1 280 × 720 with a 90° matrix |
| `quad_noaudio.fmp4` | the grid without an audio track | the forced silent AAC track: still one `soun` and one `vide` track |
| `land1080p60.fmp4` | 1 920 × 1 080, 60 fps, 6 s, 44.1 kHz mono, mixed content | frame dropping to 30 fps, resampling, down-mix, level 3.1 with 1-s key frames |
| `strip_*.jpg` | `STRIP_IMAGE`'s output (design §8.2) of the S0 image sources, canonicalised | the canonical JPEG profile; each is a fixed point of the canonicaliser |

`SHA256SUMS` lists every file. Every fMP4 file passes the spike's profile checker
(`mediatool profile`, the corrected profile of S0-3 as code); the API 29 files are one fragment each
(that encoder writes an IDR every 1 000 frames), the API 35 files two or more.
