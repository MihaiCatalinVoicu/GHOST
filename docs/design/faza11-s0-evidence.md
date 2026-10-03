# GHOST Phase 11, slice S0: media evidence (V-M checks)

| Field | Value |
|---|---|
| Design | `docs/design/faza11-media.md` (revision 3, `116cfcd`, 2026-09-25), §17.1 rows S0a/S0b, Appendix C.3 checks V-M1 … V-M24 |
| Scope of this document | every V-M check of C.3: run where this workstation can run it (the S0a checks and the emulator halves of the S0b ones), and stated as not run, with the reason, where it cannot (§25) |
| Dates | first session 2026-09-25 (API 35 complete, API 29 in part); second session 2026-10-03 … 2026-10-04 (API 29 completed, including the transcoding checks on an OpenGL ES 3 boot; V-M22 run; several API 35 checks repeated; the follow-ups this document reports); Appendix R says which check ran when and what moved between the two |
| Branch | `p11-s0` (worktree of `D:/Forum`), base `8a480a7` |
| Toolchain | Rust 1.98.1 (`ghost/rust-toolchain.toml`), cargo-ndk 4.1.2, Android NDK 30.0.16248370, JDK 17.0.20.1 (Microsoft build), Gradle 9.7.1, AGP 9.4.0, Kotlin 2.4.20, compile/target SDK 37, Media3 1.11.1, emulator 37.1.11, ExifTool 13.55 (test oracle only) |
| Emulators | `ghost-dm-api35`: `sdk_phone64_x86_64` 15 `AE3A.240806.019` userdebug, ext4 `/data`, OpenGL ES 3.0 (SwiftShader); `ghost-dm-api29`: `sdk_phone_x86_64` 10 `QSR1.210820.001` userdebug, ext4 `/data`, OpenGL ES 2.0 as booted for most checks and 3.0 with `-feature GLESDynamicVersion` (§1). Both booted `-read-only -no-window -gpu swiftshader_indirect -no-snapshot -noaudio -no-boot-anim -memory 4096 -cores 4` on port 5576, `adb root` |
| Host | Windows 11 Pro 10.0.26200, Intel Core Ultra 9 275HX (24 cores), 95.4 GiB RAM; other builds and another agent's emulator kept the host at 97–100 % CPU for long stretches, so no timing here bounds anything on a phone |
| Code | `ghost/spikes/media-s0` (evidence tooling, not product code; README there) |
| Status | Evidence for the lead. **This document does not edit `faza11-media.md`; each section ends with the exact normative correction to merge.** |

**How to read.** One section per check, numbered like the check: the question as C.3 states it, the method, the measured results with the files under `ghost/spikes/media-s0/results/` that hold them, a verdict and the normative correction. A verdict is **CONFIRMS** (the design's assumption holds as written, possibly with a precision), **CORRECTS** (it does not hold, or holds only with a change, and the correction says which) or **INCONCLUSIVE** (this workstation cannot answer it; the reason and what would answer it are stated). Corrections are numbered S0-1 … S0-20 in check order; §0.3 lists them with the sections they touch and an effort estimate, §0.4 the owner questions they raise. §25 lists what was not run and why. "§n" without a document name means `faza11-media.md`; result paths are relative to `ghost/spikes/media-s0/results/`.

---

## 0. Summary

### 0.1 Verdicts

| Check | Verdict | In one line |
|---|---|---|
| V-M1 | CONFIRMS | 48 Transformer exports through `GhostMuxer` wrote no file anywhere under `/data` (API 29 and 35); the API 29 emulator transcodes only when booted with OpenGL ES 3 (`-feature GLESDynamicVersion`) |
| V-M2 | CORRECTS | fragments start with sync samples, but `FragmentedMp4Muxer` writes no `tfdt`: the `mfra` of §8.3 has 0 entries and seeking shows wrong pictures until GHOST inserts `tfdt`; fragments are 3–4 s, and about 32 s when an encoder ignores the key-frame interval (API 29) |
| V-M3 | CONFIRMS | the constant timestamp is accepted; the box inventory is fixed, small and identical on API 29 and 35; ExifTool sees nothing outside the structural allowlist |
| V-M4 | CONFIRMS | `ImageDecoder` applies all eight EXIF orientations, in and out of the sandbox, API 29 and 35 |
| V-M5 | CORRECTS | JPEG, PNG and WebP decode in the isolated process and `SharedMemory` crosses it on API 29; HEIC and AVIF never decode there (the media server is denied to isolated apps): refused as sources |
| V-M6 | CONFIRMS | `Bitmap.compress` writes baseline `SOF0`; with `setGainmap(null)` nothing follows `EOI`; the JFIF and ICC segments it always adds are what the canonicaliser drops |
| V-M7 | CORRECTS | no native code, but eight third-party artifacts (not two) and `media3-database`; +1 247 377 B |
| V-M8 | CONFIRMS | `aead-stream` 0.6.0 resolves on the product's `aead` 0.6.1; the format of §3–§4 implemented from the text agrees with `StreamBE32` and with an independent JDK replay (145/145 values, 15/15 refusals) |
| V-M9 | INCONCLUSIVE | needs the arm64 reference phone; x86_64 emulators seal at 155–283 MB/s and open at 227–340 MB/s, a 50 MiB object streams in a few MB |
| V-M10 | INCONCLUSIVE | not run: needs a staging relay as an onion service |
| V-M11 | CONFIRMS | reading the picked stream wrote nothing into the app's directories (API 29 and 35) |
| V-M12 | INCONCLUSIVE | the reference devices are S0b; the emulators' software encoders emit no SEI and start every AAC block with a CPE |
| V-M13 | CORRECTS | with diagnostics off ExoPlayer still creates a platform playback session on API 31+ and its id reaches the audio-track record |
| V-M14 | CORRECTS | R8 removes the cache and download classes, but the HTTP/UDP/file data sources, `InAppMp4Muxer` and `MediaMetricsListener` stay |
| V-M15 | INCONCLUSIVE | needs an MTE device; the per-process manifest form is accepted and parsed (API 35), inert on API 29 |
| V-M16 | CORRECTS | `setLastModified(0)` zeroes `mtime` but leaves `atime` at the creation second; `setTimes(0, 0)` zeroes both (ext4; f2fs unmeasured) |
| V-M17 | CORRECTS | forced encoding holds (no source unit or canary survives), but the colour signalling is the source's (and wrong on API 29) unless GHOST sets BT.709 limited, which converts the pixels |
| V-M18 | CONFIRMS / INCONCLUSIVE | a fresh process per request binds, decodes and dies (100/100 on API 29 and 35); whether 0.2–0.8 s per start is acceptable needs a criterion and the phone |
| V-M19 | CONFIRMS | the Application runs in `:mdec` and the early return is required; no provider runs there; without it a bind never connects |
| V-M20 | CONFIRMS | FLAG_SECURE (29, 35) and `setRecentsScreenshotEnabled(false)` (35) keep media pixels out of task snapshots; a native `:mdec` crash puts plaintext into tombstones, dropbox and a bug report, as L9-M8 declares |
| V-M21 | CORRECTS | the OS keeps more than recents: decoded thumbnails of the pictures outside GHOST (both levels, in shared storage too; on API 29 for every picture shown), a placeholder naming the picked item (API 35), a per-file pick counter and GHOST's last folder and time (API 29); the photo picker zeroes the location |
| V-M22 | CORRECTS | the overshoot stays small only on easy content; hard content overshoots by +29 % to +4 232 % on API 35 (either mode) and by about +150 % on API 29 (VBR, its only mode); CBR is the worse mode where both exist; an export can stall |
| V-M23 | CONFIRMS | the first frame reaches an `ImageReader` and no file is written (API 29 and 35); it arrives in the coded orientation, with a luma range that differs by level |
| V-M24 | CORRECTS | the parameters come out exactly once `GhostMuxer` forwards the rotation, GHOST supplies down-mix matrices for 3–8 channels and portrait encoding stays off |

### 0.2 Values to freeze

| Value | Measured | Evidence |
|---|---|---|
| Fragment length | the smallest multiple of the key-frame interval ≥ 2 s: 3 s at Media3's 1-s interval; 4 s for a 60-fps source; the encoder's own spacing if it ignores the interval (about 32 s on API 29's emulator encoder) | V-M2 |
| `tfdt` insertion | 20 B per `traf` (+160 B for a 12-s video), every `trun` `data_offset` and `tfhd` `base_data_offset` rewritten | V-M2 |
| Fragment bound (new) | ≤ 16 MiB and ≤ 40 s of video per fragment, else the export fails | V-M2, S0-2 |
| Canonical fMP4 inventory | `ftyp` (`isom`, 131 072, `isom iso2 mp41`), `moov` (`mvhd` v0 timescale 10 000; `trak` audio 1, video 2; `mvex`/`trex`), (`moof` = `mfhd` + `traf` = `tfhd` 0x1 + `tfdt` + `trun` 0x701, `mdat`)*, `mfra`; nothing else | V-M3 |
| Colour | `colr` `nclx` (1, 1, 1, limited); SPS VUI without colour description or (1, 1, 1, limited) | V-M17 |
| Coded geometry | 1 280 × 720 with a `tkhd` matrix of 0°, 90°, 180° or 270°; portrait encoding off | V-M24 |
| Down-mix | explicit matrices for 3 … 8 input channels (5.1: BS.775 without LFE) | V-M24 |
| JPEG APPn dropped per image | APP0 18 B + APP2 ICC 474 B (API 35) / 554 B (API 29) | V-M6 |
| Image sources | JPEG, PNG, static WebP; HEIC/HEIF/AVIF refused | V-M5 |
| File times | `mtime` = `atime` = 0 via `setTimes`; `ctime` and inode adjacency declared | V-M16 |
| Media3 transitive set | Guava 33.3.1-android, `failureaccess` 1.0.2, `jsr305` 3.0.2, `checker-qual` 3.43.0, `error_prone_annotations` 2.28.0, `j2objc-annotations` 3.0.0, `kotlinx-coroutines-guava` 1.9.0, `exifinterface` 1.3.6, `media3-database` 1.11.1 | V-M7 |
| R8 delta of the design's Media3 use | +1 247 377 B, no `.so` | V-M7 |
| Oversize retry | one retry at `bitrate × 0.9 × capacity / projected size`, then `TOO_LARGE` | V-M22, S0-18 |
| Stall watchdog | an export with no progress for 30 s is cancelled | V-M22, S0-18 |
| Isolated-process criterion (proposed) | p90 of bind + 320-px decode + reply ≤ 250 ms on the reference phone | V-M18, Q-S2 |
| Vector file | `rust/vectors/media_object.txt`, 217 lines, SHA-256 `e0ea7a82…0ed5` | V-M8 |

### 0.3 Normative corrections (for the lead to merge)

| # | Check | Sections | Correction (short) | Effort |
|---|---|---|---|---|
| S0-1 | V-M1 | §15.6, §6.2, §15.8 | API 29 emulator job booted with `GLESDynamicVersion`; a GL failure maps to `UNSUPPORTED_SOURCE`/`GL_UNAVAILABLE`; the root search must prove it ran as root | 0.5 d |
| S0-2 | V-M2 | §8.3, §10.2, §15.8, MC-M24 | `tfdt` inserted by the sealing channel; `mfra` from `tfdt`; fragment rule and bound; duration from the manifest; content-identified seek test | 3 d |
| S0-3 | V-M3 | §8.3 | the canonical fMP4 profile written out from the goldens | 1 d |
| S0-4 | V-M5 | §6.1, §1.3, §9.1, §9.2, §15.7, Q9 | HEIC/HEIF/AVIF refused as sources; Q9 answered; Q-S1 | 0.5 d |
| S0-5 | V-M7 | §16.3, §16.1 G-L2, G-M2, G-M1, Q28 | the transitive set and its licences; `media3-database` allowed and its provider class banned; size delta | 1 d |
| S0-6 | V-M8 | §3.2, §3.9, §16.3 | label sets clarified; negative cases as data in the vector file; distinct nonces per vector | 1 d |
| S0-7 | V-M11 | §6.1, G-M1 | picked URIs opened read-only, the persistable grant never taken (API 29 grants write) | 0.25 d |
| S0-8 | V-M12 | C.3 V-M12 (S0b) | full AAC element walk; key-frame spacing per encoder | 0.5 d |
| S0-9 | V-M13 | §10.2, L9-M8, B.4 | the playback session that diagnostics-off does not stop, declared | 0.25 d |
| S0-10 | V-M14 | §10.3, G-M3, T44 | release-dex absence check of the measured removable set only | 1 d |
| S0-11 | V-M15 | C.3 V-M15 (S0b) | the MTE check reads a bound isolated instance (instance-suffixed name) | 0.25 d |
| S0-12 | V-M16 | §10.4, §12.4, L9-M6, §15.5 | `setTimes(0, 0)` instead of `setLastModified(0)`; `atime` zeroed and asserted | 0.5 d |
| S0-13 | V-M17 | §8.3, §15.7 | encoder colour forced to SDR BT.709 limited; `colr`/VUI rule; luma-range corpus test | 1 d |
| S0-14 | V-M18 | §9.2, Q25 | measured cost and a criterion for previews; Q-S2 | 0.25 d |
| S0-15 | V-M19 | §9.2 | the unguarded bind never connects: the binding test asserts a 2-s connection | 0.25 d |
| S0-16 | V-M20 | §10.3, L9-M8, B.4, §15.8 | snapshot controls measured; tombstone residue described; the scan decodes hex dumps, `.pb` and gzip | 1 d |
| S0-17 | V-M21 | L9-M15, §6.1, B, threat model, §15.8 | the measured picker residues per API level; Q-S4 | 0.5 d |
| S0-18 | V-M22 | §6.1, §6.2, §8.3, R-M17, C.3 | limits bound the source only; cancel on `OVERSIZE` and retry once smaller; VBR; stall watchdog; Q-S3 | 2 d |
| S0-19 | V-M23 | §6.2, §15.7 | the preview's rotation from `Format.rotationDegrees`; YUV-to-RGB with the image's own range | 0.5 d |
| S0-20 | V-M24 | §8.3, D29, §15.7, PM-M26 | `GhostMuxer` writes the rotation; portrait encoding off; explicit down-mix matrices; walker geometry | 1 d |

The efforts are S1 implementation days including tests, about 15.5 days in all; none needs a new dependency.

### 0.4 Owner questions raised

| # | From | Question | Default if unanswered |
|---|---|---|---|
| Q-S1 | V-M5 | HEIC/HEIF and AVIF photos cannot be decoded in the sandbox: refuse them (the user sees a message), or relax D17 for HEIC sources only (a main-process decode of the user's own file)? | refuse |
| Q-S2 | V-M18 | Accept "p90 of bind + 320-px decode + reply ≤ 250 ms on the reference mid-range phone" as the criterion for one isolated process per preview (Q25's fallback for previews above it)? | accept |
| Q-S3 | V-M22 | Hard content overshoots 2 Mbit/s by 1.3× to 43×. Keep 160 s / 85 s as source limits with an in-flight `OVERSIZE` cancel and one smaller retry (default), or also lower the limits? | retry, limits kept |
| Q-S4 | V-M21 | The system picker leaves thumbnails of the pictures outside GHOST on both measured levels, and on API 29 also GHOST's package name with the folder and time of its last pick, a pick counter and thumbnails of every picture shown (in shared storage). Declare only, show a one-time notice before the first pick, or (API 29) refuse picking? | declare |
| Q-S5 | V-M7 | Allowlist the four annotation-only artifacts that Media3 pulls in (`jsr305`, `checker-qual`, `error_prone_annotations`, `j2objc-annotations`), or exclude them globally in `:media`'s Gradle file if `:app` still builds and R8's output is unchanged? | exclude, if S1 shows it is clean |

### 0.5 The spike

`ghost/spikes/media-s0` is **evidence tooling, not product code** (its README says so first): two Rust crates with their own `[workspace]` and lock files (`rust/`, `rust/crashlib/`), a JDK program (`jvm/`), a Gradle build of its own (`android/`: the probe app, the R8 probe, the MTE manifest probe) and shell scripts (`scripts/`). It is outside the ghost Cargo workspace and outside `ghost/android`, no gate scans it, and nothing in it ships. **Fate:** S1 re-implements what it proves in `ghost-client-media` and `:media` under review (the reference format, the vector file, the walker rules, `GhostMuxer`, the sandbox protocol); the scripts that turn into gates (`exif-oracle.sh`, the root search, the picker and crash scans) move to `ghost/scripts/gates` with fixtures; the directory is then deleted.

Reproduce (from `ghost/spikes/media-s0`, with the environment and the boot lines of its README):

```
(cd rust && cargo test --release --locked -- --nocapture)            # V-M8 and the vector file
java jvm/MediaVectors.java rust/vectors/media_object.txt               # V-M8, JDK replay
(cd android && ./gradlew --no-daemon :probe:assembleDebug :mteprobe:assembleDebug \
    :r8probe:assembleBaseRelease :r8probe:assembleMediaRelease)       # V-M7, V-M14
bash scripts/run-all.sh 35 --sources generate                         # API 35
bash scripts/run-all.sh 35 --steps short,long                         # V-M22 on API 35
bash scripts/run-all.sh 29 --golden-from work/api35/out                # API 29, ES 2.0 boot
bash scripts/run-all.sh 29gles --steps install,env,glinfo,sources,vm1,goldens,seek,analyse,preview,short
bash scripts/vm21-picker.sh 29 work/api35/src/orient6.jpg             # V-M21, V-M11 (and with 35)
```

---

## 1. V-M1: does Transformer with `GhostMuxer` write any file?

**Question (C.3).** Transformer with `GhostMuxer` writes no file anywhere (file inventory and `FileObserver` on every app directory during 20 transcodes). §8.4: the default `InAppMp4Muxer` opens `new FileOutputStream(path)`; the Transformer class itself touches no file; whether a component it drives does is the open question.

**Method.** The `transcode` probe with `-e set basic -e observe 1` runs 24 exports (the `basic` set twice: the 720p30 matching source in the five configurations of V-M17, the 1080p60, portrait, rotated and VGA sources, VBR) with `GhostMuxer` writing into memory, after (a) a recursive inventory (path, size, `lastModified`) of every directory an app can write without a permission (§15.8 item 1's list: `/data/user/0/<pkg>` with `files`, `cache`, `code_cache`, `no_backup`, `databases`, `shared_prefs`, `app_*`; `/data/user_de/0/<pkg>`; the app's external directories where they exist) and (b) a `FileObserver` on each of those directories (recursively attached; create, modify, close-write, move, delete, attribute). After the 24 exports the inventory is diffed and the events listed; a root shell then lists every regular file under `/data` newer than a marker touched before the run (`find /data -xdev -newer`, refusing to report unless `adbd` answers as root). The path Transformer requires (`start(composition, path)`) is a never-created `files/never-written-*.mp4`; each export records whether it exists afterwards.

**Results.**
- **API 35** (2026-09-25, `results/api35/transcode-vm1-observe.txt`, `-rootfind.txt`): **24 of 24 exports succeeded; 0 `FileObserver` events on 11 directories; 0 inventory changes**; the offered path never existed. Everything newer than the marker under all of `/data`: the probe's ART profile (`/data/misc/profiles/cur/0/<pkg>/primary.prof`), `/data/system/package-dex-usage.pb` and two `powerstats` logs, none of them media.
- **API 29 as booted for the other checks** (`-gpu swiftshader_indirect`, 2026-09-25 and 2026-10-03, `results/api29/transcode-vm1-observe.txt`): **22 of 24 exports fail** with `ERROR_CODE_VIDEO_FRAME_PROCESSING_FAILED`, cause chain `VideoFrameProcessingException ← GlUtil$GlException: eglChooseConfig failed`; only the two `PLAIN_DEFAULTS` exports (no effect, transmux) succeed. That boot exposes OpenGL ES 2.0 only (`ro.opengles.version` 131072, `ANDROID_EMU_gles_max_version_2`; API 35: 196608, ES 3.0), and Media3 1.11.1's frame processor cannot obtain its EGL configuration. 0 events and 0 inventory changes for the transmuxes and the failed attempts; that run's root search came back empty without the root check of the current script and is not counted.
- **API 29 with `-feature GLESDynamicVersion`** (2026-10-04, `results/api29gles/`): the same image, the same boot line plus that flag, exposes **OpenGL ES 3.0** (SwiftShader 4.0.0.1, `ro.opengles.version` 196608). **24 of 24 exports succeeded**, with `OMX.google.h264.encoder` and `OMX.google.aac.encoder` (no CBR on that encoder, so every export ran VBR); **0 `FileObserver` events on 9 directories, 0 inventory changes**; the root search found only the probe's ART profile. Every API 29 number of V-M3, V-M17, V-M22 and V-M24 marked "API 29" comes from this boot.

**Verdict: CONFIRMS** on API 29 and API 35 (API 37: no image, §25): Transformer driving `GhostMuxer` wrote no file anywhere under `/data` in 48 exports. Every re-encoded video frame goes through Transformer's OpenGL frame processor, which found no usable EGL configuration on the ES 2.0 boot and worked on the ES 3.0 one: an API 29 emulator booted without `GLESDynamicVersion` cannot transcode at all.

**Normative correction (S0-1).**
1. §15.6, emulator job (and the device-suite boot line of F9 §22.32 it reuses): "API 29 images are booted with `-feature GLESDynamicVersion` (OpenGL ES 3.0 under SwiftShader); without it Media3 1.11.1's frame processor fails every export with `eglChooseConfig failed` (S0 V-M1), and the media suite would test nothing on API 29."
2. §6.2, `GhostTranscoder` errors: "a `VideoFrameProcessingException` from the GL stack maps to `UNSUPPORTED_SOURCE` with the detail `GL_UNAVAILABLE`, counted (a device without OpenGL ES 3 cannot send video; images are unaffected)". Whether any supported phone lacks ES 3.0 is a device question (S0b checklist line).
3. §15.8 item 1's root search keeps the guard of `scripts/run-all.sh` (`rootfind`): it reports nothing unless `adbd` answers as root and ends a complete listing with an explicit end line, so an empty answer is never mistaken for a clean one.

---

## 2. V-M2: sync samples at fragment starts, and seeking through a GHOST `mfra`

**Question (C.3).** Does `FragmentedMp4Muxer` start every fragment with a sync sample, and does `FragmentedMp4Extractor` with `FLAG_READ_MFRA_FOR_SEEK_MAP` seek through a GHOST-built `mfra` (§8.3, FR-7.4)?

**Method.**
1. *Fragment structure.* Every Transformer output of V-M1/V-M24 (20 files on API 35) goes through `mediatool mp4`, which walks the boxes, sums each video `trun`'s sample durations, and reports per fragment whether its first sample is a sync sample (`results/api35/mp4-report.txt`). The writer's flush rule was read in the 1.11.1 bytecode (`javap -c androidx.media3.muxer.FragmentedMp4Writer.shouldFlushPendingSamples`), and every class of `media3-muxer` 1.11.1 was searched for the box names it can write.
2. *The `mfra` of §8.3 as written:* one `tfra` (version 1) for the video track, one entry per `moof`, time = that `moof`'s `tfdt`, offset = the `moof`'s file offset, traf/trun/sample numbers 1; then `mfro` (`Mp4Mini.buildMfra`, its Rust twin `mp4::build_mfra`).
3. *Corrections under test:* (a) the `tfra` times taken from the running sum of the video `trun` durations instead of `tfdt`; (b) a version-1 `tfdt` inserted after the `tfhd` of every `traf` (20 B per `traf`; every `trun` `data_offset` grows by the bytes added to its `moof`, and every `tfhd` `base_data_offset`, which `FragmentedMp4Writer` writes as an absolute file offset with flag 0x1, is rewritten), then the `mfra` built from those `tfdt`s (`Mp4Mini.insertTfdt`).
4. *Extractor half* (`seek` probe, no decoding): `FragmentedMp4Extractor(SubtitleParser.Factory.UNSUPPORTED, flags)` driven over the bytes; 50 random targets (seeded) in the 12-s golden `match720p30__DESIGN.mp4`; for each, `getSeekPoints(t)`, `seek(position, t)` as `ProgressiveMediaPeriod` does, then the first video sample's time and flags. Pass: a sync sample at a time in `[t − 1 s, t]` (the encoder's key-frame interval is 1 s).
5. *Player half:* ExoPlayer over the same bytes with an fMP4-only extractors factory (the flag set), video into an `ImageReader`; after `seekTo(t)` the first rendered frame's PTS **and its content**: every source frame carries its index as 16 luma blocks (`SourceMaker.fillFrame`), so the frame shown is identified, and the expected one is `⌊t · 30⌋`. A timestamp check alone cannot see a frame shown at the right time with the wrong picture.

**Results** (API 35, `results/api35/seek.txt`, 2026-09-25).
- **Every fragment starts with a sync sample**: 20 of 20 outputs, every fragment (`starting_with_sync` = fragments). Fragments are **not 2 s long**: 3.0 s with the encoder's 1-s key-frame interval, 4.0 s for the 60-fps source (its output had a sync sample every 2 s). The 1.11.1 bytecode explains both: a fragment is flushed only when a video **key frame** arrives and the pending video samples span `≥ fragmentDurationUs` (2 000 000 µs) from first to last presentation time, so at 1-s key frames the span at the 2-s key frame is 1.967 s and the fragment closes at 3 s.
- **`FragmentedMp4Muxer` 1.11.1 writes no `tfdt`.** Every `traf` is `tfhd` + `trun`; no class of `media3-muxer` 1.11.1 contains the string `tfdt` (nor `mfra`, `tfra`, `sidx`, `mehd`), while `moof`, `traf`, `tfhd`, `trun`, `mvex`, `trex` are present. So the `mfra` of §8.3 as written ("time = that `moof`'s `tfdt`") has **0 entries** (48 B).
- `mfra` from summed durations: 4 entries at 0, 3, 6, 9 s (90 kHz: 0, 270 000, 540 000, 810 000), offsets 1 147 … 4 477 190, 124 B. `tfdt` inserted: +160 B (4 `moof` × 2 `traf` × 20 B).

| Variant (API 35) | Seek map | Extractor: first sample sync / within `[t−1 s, t]` / max lag | Player: PTS within 1 frame / **picture within 1 frame** / worst picture error |
|---|---|---|---|
| `mfra` as designed (from `tfdt`: 0 entries) + flag | `MfraSeekMap`, seekable, every point (0, 1 147) | 50 / 20 / 6.85 s | 50 / 50 / 1 frame (decodes from the start: correct, slow) |
| `mfra` from summed durations, no `tfdt`, + flag | `MfraSeekMap`, seekable, points at 0/3/6/9 s | 50 / 20 / 6.85 s (first sample always stamped 2.000 s) | 50 / **41** / **91 frames** (e.g. target 5.942 s showed frame 269, expected 178) |
| `tfdt` inserted + `mfra` from `tfdt` + flag | `MfraSeekMap`, seekable | **50 / 50 / 0.99 s** (lands on the key frame before the target inside the fragment) | **50 / 50 / 1 frame** |
| `mfra` without the flag | `Unseekable` | — | — |
| no `mfra`, flag set | `Unseekable` | — | — |

Without `tfdt` the extractor stamps the samples after a seek with a stale decode time (the time it carried from the fragment it parsed before the seek), so the player believes it is at the target and shows another picture: 9 of 50 seeks showed a frame up to 3 s away from the target with a correct-looking timestamp. With `tfdt` the extractor also skips to the key frame at or before the target inside the fragment. The seek map has no duration (`durationUs` unset): the fMP4 carries none (`mvhd`, `tkhd`, `mdhd` durations are 0 and there is no `mehd`, V-M3), so the player's duration is unknown unless GHOST supplies it.
- **API 29 over the API 35 golden** (2026-10-03, `results/api29/seek.txt`, `seek-player.txt`; pushed because that boot could not transcode, V-M1): the extractor half gives exactly the API 35 numbers (the extractor is Java; 50 / 20 / 6.85 s without `tfdt`, 50 / 50 / 0.99 s with it). The player half, timestamps only (a `PRIVATE` reader), 20 seeks: without `tfdt` **3 of 20 rendered PTS were off by up to 2.83 s** (target 8.764 s rendered 5.933 s); with `tfdt` 20 of 20 within one frame. A repeat with a YUV reader (2026-10-04, `seek-player-yuv.txt`): without `tfdt` 1 of 20 off (by 1.05 s), with `tfdt` 20 of 20. Its content check is not usable on this image: the luma blocks decode to impossible frame numbers even where the timestamp is right (an image-layout difference the probe does not handle), so API 29 rests on timestamps. The first YUV attempt aborted the probe inside ART's JIT (`elf_debug_reader.h:64 Check failed` in `PackElfFileForJIT`, Android 10's debug-info packing for a debuggable app; `seek-player-yuv-jit-abort.txt`), a platform fault unrelated to media that `cmd package compile -m speed -f` (AOT, no JIT) avoids.
- **API 29's own golden** (the GLES 3 boot of §1, 2026-10-04, `results/api29gles/seek.txt`, `transcode-longvbr.txt`): `OMX.google.h264.encoder` ignores the 1-s key-frame interval Transformer requests by default: it wrote **one IDR in every export of 6–12 s and five in each 160-s export** (4 799 frames: on average one IDR every 32 s). Every output of 6–12 s is therefore **one fragment** (one `moof`, one `tfra` entry) and a 160-s output five fragments, about 32 s each on average (8.6 MB at 2.1 Mbit/s, 21 MB for the `mixed` source); by the writer's flush rule above (a fragment is written when the next key frame arrives, or at the end), `FragmentedMp4Writer` holds a whole fragment in memory before any byte reaches the channel (the app's `VmHWM` rose by 39 MB during the `mixed` export). Seeking such a file is correct but costs a decode from the fragment's start; the probe's target generator (which takes the duration from the fragment times) degenerated to t = 0 on the 12-s golden, so its seek numbers carry no information, and its player half was stopped by hand after its first variant (`seek-player.txt`).

**Verdict: CORRECTS** the design. Fragments do start with sync samples (API 29 and 35), and the flag plus an `mfra` makes the extractor seekable, but the `mfra` cannot be built from `tfdt` (there is none) and seeking is only correct when GHOST adds `tfdt` boxes; fragments are 3–4 s, not 2 s, and as long as the encoder's real key-frame spacing when it ignores the requested interval (about 32 s on API 29's emulator encoder).

**Normative correction (S0-2).**
1. §8.3 `GhostMuxer` point 4: replace "Fragments of 2 s (`FragmentedMp4Muxer`'s default fragment duration)" by "Fragments as `FragmentedMp4Writer` 1.11.1 cuts them: a fragment closes at the first video key frame once the pending video samples span ≥ 2 s, so its length is the smallest multiple of the key-frame interval above 2 s (3 s at Media3's default 1-s interval, `VideoEncoderSettings.DEFAULT_I_FRAME_INTERVAL_SECONDS`, which `GhostTranscoder` sets explicitly with `setiFrameIntervalSeconds(1)`; measured 3 s, and 4 s for a 60-fps source whose output had a key frame every 2 s, presumably because the encoder is configured with the source's frame rate before frames are dropped). Every fragment starts with a sync sample (measured on every S0 output); the walker requires it."
2. §8.3, `SealingChannel` paragraph: "`FragmentedMp4Muxer` 1.11.1 writes no `tfdt` (S0 V-M2). Before any byte reaches `sealAppend`, `GhostMuxer`'s channel inserts after the `tfhd` of every `traf` a version-1 `tfdt` whose value is the running sum of that track's `trun` sample durations in its `mdhd` timescale, adds 20 B per inserted box to the `moof` and `traf` sizes and to every `trun` `data_offset` of that `moof`, and rewrites each `tfhd` `base_data_offset` (absolute, flag 0x1) by the bytes inserted before it. The channel buffers one `moof` at a time (≤ 8 KiB measured at 3-s fragments; it grows by 12 B per sample with the fragment) and passes `mdat` through. `sealFinish` appends an `mfra` whose `tfra` (version 1, video track only, traf/trun/sample number 1) has one entry per `moof` with time = that `moof`'s video `tfdt` and offset = its file offset in the sealed stream, then `mfro`."
3. §8.3, canonical fMP4 profile: "each `traf` is exactly `tfhd`, `tfdt` (version 1, value equal to the running sum of the track's previous `trun` durations), `trun`; `tfra` entries point at `moof` boxes whose video `tfdt` equals the entry's time" (the last clause is kept and becomes checkable).
4. §10.2: "The fMP4 has no duration (`mvhd`/`tkhd`/`mdhd` 0, no `mehd`) and Media3's `MfraSeekMap` reports none: `MediaHandle` exposes the manifest's `duration_ms`, and the UI and the seek tests use it."
5. §15.8 item 3: replace "land within one fragment duration of the target" by "show the target frame ±1 (identified by content, not by timestamp: S0 V-M2 showed correct timestamps on wrong pictures without `tfdt`)"; mutant MC-M24 (new, `media-emulator`): "`tfdt` insertion removed" must be caught by that check. The test draws its targets from the manifest's `duration_ms`, never from fragment times (S0's probe drew them from fragment times and degenerated on a one-fragment file).
6. §8.3, walker: "a fragment whose `moof` + `mdat` exceed 16 MiB, or whose video samples span more than 40 s, fails the export (`NON_CANONICAL` in the sealer, `UNSUPPORTED_SOURCE` for the user): `FragmentedMp4Writer` buffers a whole fragment in memory until the next key frame, and an encoder that ignores the requested key-frame interval makes fragments as long as its own spacing (S0 V-M2: API 29's `OMX.google.h264.encoder` put an IDR every 32 s on average, so about 21 MB of the `mixed` source sat in the writer's memory before the channel saw a byte)." The bound is a memory bound first; S0b's V-M12 records each reference encoder's real key-frame spacing, and the lead may tighten the duration bound from it.

---

## 3. V-M3: the constant timestamp and the box inventory of `FragmentedMp4Muxer` 1.11.1

**Question (C.3).** Is `Mp4TimestampData` with a constant accepted, and is the box inventory of 1.11.1 stable enough to pin as the canonical fMP4 profile's goldens?

**Method.** `GhostMuxer` (`android/probe/.../GhostMuxer.kt`) is §8.3's wrapper as written: `FragmentedMp4Muxer.Builder(WritableByteChannel)` over an in-memory, strictly sequential channel; `addMetadataEntry(Mp4TimestampData(0, 0))` once at construction; every entry Transformer offers is recorded and dropped except `Mp4OrientationData` with 0/90/180/270; only an AVC and an AAC track; the SEI filter. 24 exports on API 35 (the `basic` set twice: the matching source in five configurations, 1080p60, portrait, rotated, VGA, VBR) plus the five `fixes` exports, the 16 distinct outputs (one per configuration) saved, pulled and walked by `mediatool mp4` and read by ExifTool 13.55 through `scripts/exif-oracle.sh` (T43's reading: every tag outside a structural allowlist is listed).

**Results** (API 35; `results/api35/transcode-save.txt`, `transcode-fixes.txt`, `mp4-report.txt`, `exif-oracle-video.txt`).
- **What Transformer offers to `addMetadataEntry`:** for every source, per track, `MdtaMetadataEntry` `com.android.version` = 15, `Mp4LocationData` (the planted 46.7712, 23.6235), `Mp4TimestampData` (the source's creation and modification time, timescale 10 000) and a `ThumbnailMetadata` (presentation time 0). `GhostMuxer` forwarded none of them; it forwarded its own `Mp4TimestampData(0, 0)`. **No `Mp4OrientationData` was ever offered**, not even for the rotated source (V-M24).
- **The constant is accepted:** `mvhd`, both `tkhd` and both `mdhd` have creation = modification = 0 and duration 0 in all 16 saved outputs (and the two seek variants of V-M2); ExifTool reads `0000:00:00 00:00:00` for all six dates.
- **Inventory (identical in all 16 saved outputs apart from counts):** top level `ftyp` (major `isom`, minor 131 072, compatible `isom`, `iso2`, `mp41`), `moov`, then (`moof`, `mdat`) pairs. `moov` = `mvhd` (v0, timescale 10 000, `next_track_ID` 3), two `trak`, `mvex` with two `trex` (all defaults 0). Each `trak` = `tkhd` (v0, flags 0x7) and `mdia` = `mdhd` (v0; 48 000 for audio, 90 000 for video), `hdlr` (`soun` "SoundHandle" / `vide` "VideoHandle"), `minf` = `smhd` or `vmhd`, `dinf`/`dref`, `stbl` = `stsd`, `stts`, `stsz`, `stsc`, `stco` (empty) and, for video only, `stss`. Sample entries: `mp4a` (2 channels, 16-bit, 48 000 Hz) with `esds` (ASC `0x1190`: AAC-LC, 48 kHz, 2 channels); `avc1` (1 280 × 720 or 720 × 1 280, empty compressor name) with `avcC` (4-byte NAL lengths), `pasp` 1:1 and `colr` `nclx`. `moof` = `mfhd` (sequence 1 …) and one `traf` per track = `tfhd` (flags 0x1, absolute `base_data_offset` = the `moof`'s offset) and `trun` (flags 0x701: data offset, per-sample duration, size and flags). **Absent:** `tfdt` (V-M2), `edts`, `udta`, `meta`, `ilst`, `keys`, `uuid`, `free`/`skip`, `sidx`, `mehd`, `mfra`. **Track order:** the audio track is track 1 and the video track 2 in every transcode (Transformer adds audio first); the transmuxed control had video first.
- ExifTool: every DESIGN output shows **0 tags outside the structural allowlist and 0 canaries**; the only non-dimensional groups are `[QuickTime]`/`[TrackN]` header fields with constant values and `MovieFragmentSequence` (the `mfhd` numbers). Two allowlisted fields carry source-dependent **values**: `MatrixCoefficients` (BT.601 for the BT.601 source, BT.709 otherwise) and the `colr` box behind it (V-M17), and the `tkhd` matrix carries the rotation (V-M24).

- **API 29** (the GLES 3 boot of §1, 2026-10-04, `results/api29gles/mp4-report.txt`, `exif-oracle-video.txt`): the 16 saved outputs have exactly the same box inventory (same `ftyp`, the same `moov` tree, audio track 1 and video track 2, `tfhd` flags 0x1, `trun` flags 0x701, no `tfdt`), all times 0, and ExifTool finds 0 tags outside the allowlist and 0 canaries in all 18 files; what differs is content, not structure: one `moof` per output (V-M2), the encoder's SPS without a colour description, and `colr` values (V-M17).

**Verdict: CONFIRMS** on API 29 and 35 (the constant timestamp works; the inventory is fixed, small and the same on both levels), with the goldens recorded here and three facts the canonical profile must state.

**Normative correction (S0-3).** §8.3, "Canonical fMP4 profile": replace "inside, only the box types and fixed field values that `FragmentedMp4Muxer` 1.11.x writes … pinned by S0 goldens" by the measured profile: "top level exactly `ftyp` (`isom`, minor 131 072, `isom iso2 mp41`), `moov`, then (`moof`, `mdat`) pairs, then GHOST's `mfra`; `moov` = `mvhd` (v0, times 0, duration 0, timescale 10 000), one `soun` and one `vide` `trak` in either order (Transformer adds audio first; the walker accepts both orders and requires distinct track IDs 1 and 2), `mvex` with one default `trex` per track; each `trak` = `tkhd` (v0, flags 7, times and duration 0, the matrix of 0°, 90°, 180° or 270°), `mdia` (`mdhd` v0 with timescale 48 000 or 90 000, times and duration 0, the packed language field 0 as written; `hdlr` `soun` "SoundHandle" or `vide` "VideoHandle"; `minf` with `smhd`/`vmhd`, `dinf`/`dref` (one `url ` self-reference), `stbl` with `stsd`, empty `stts`, `stsz`, `stsc`, `stco`, and `stss` for video only); sample entries `mp4a`+`esds` (AAC-LC, 48 kHz, 2 channels) and `avc1`+`avcC`+`pasp` (1:1)+`colr` `nclx` (1, 1, 1, limited range; S0-13); `moof` = `mfhd` + per track `traf` = `tfhd` (flags 0x1) + `tfdt` (S0-2) + `trun` (flags 0x701). Nothing else; `edts`, `udta`, `meta`, `ilst`, `keys`, `uuid`, `free`, `skip`, `sidx`, `mehd` are refused (none appears in the 16 saved S0 outputs)". G-M8's goldens are `results/api35/mp4-report.txt`'s DESIGN rows.

---

## 4. V-M4: `ImageDecoder` and EXIF orientation

**Question (C.3).** Does `ImageDecoder` apply the EXIF orientation on API 29–37, so that `STRIP_IMAGE` bakes it in without `ExifInterface`?

**Method.** `SourceMaker.makeOrientationCorpus` writes eight JPEGs (`orient1.jpg` … `orient8.jpg`): a 600 × 400 picture of four coloured quadrants (TL red, TR green, BL blue, BR white), stored with the inverse of each EXIF orientation's display transform (so every file *displays* as R G / B W when the orientation is honoured; orientations 5–8 are stored 400 × 600), the EXIF `Orientation` tag set by AndroidX `ExifInterface`, and planted canaries (Make, Model, Software, serial, unique id, `DateTimeOriginal`, `OffsetTimeOriginal`, GPS). The `orient` probe decodes each file four ways and classifies the four quadrant centres: `ImageDecoder` in the main process (software allocator, from a `ByteBuffer`), `BitmapFactory` (control), `ImageDecoder` inside a fresh isolated instance from a read-only `SharedMemory` region (§9.2), and the full `STRIP_IMAGE` of §8.2 in another fresh instance, whose output JPEG is decoded again in the main process. API 29 and API 35; the sources were generated once on API 35 and pushed unchanged to API 29 (`results/api29/sources-pushed.txt`).

**Results** (`results/api{29,35}/orient.txt`; API 35 re-run 2026-10-03: identical).

| EXIF orientation | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---|---|---|---|---|---|---|---|
| `ImageDecoder`, main process, API 29 and 35 | RGBW | RGBW | RGBW | RGBW | RGBW | RGBW | RGBW | RGBW |
| `ImageDecoder`, isolated instance, API 29 and 35 | RGBW | RGBW | RGBW | RGBW | RGBW | RGBW | RGBW | RGBW |
| `STRIP_IMAGE` output (512 × 336, q 85), API 29 and 35 | RGBW | RGBW | RGBW | RGBW | RGBW | RGBW | RGBW | RGBW |
| `BitmapFactory` (control), API 29 and 35 | RGBW | GRWB | WBGR | BWRG | RBGW¹ | GWRB¹ | WGBR¹ | BRWG¹ |

¹ 400 × 600: `BitmapFactory` returns the stored pixels. Every `ImageDecoder` result is 600 × 400, the displayed size.

**Verdict: CONFIRMS** the design on API 29 and 35 (API 37: no image here, §25): `ImageDecoder` applies all eight EXIF orientations, in the main process and inside the isolated process, so `STRIP_IMAGE` needs no `ExifInterface` fallback; the control shows that `BitmapFactory` ignores the tag (7 of 8 wrong), which is one more reason G-M3 confines both.

**Normative correction.** None. (§8.2's "apply the EXIF orientation if `ImageDecoder` did not (V-M4: ExifInterface in the sandbox is the fallback)" may be shortened to "`ImageDecoder` applies the EXIF orientation (V-M4, API 29 and 35)"; the conditional `exifinterface` row of §16.3 is then moot, and V-M7 shows that `exifinterface` ships anyway as a Media3 dependency.)

---

## 5. V-M5: what decodes inside the isolated process, and `SharedMemory` on API 29

**Question (C.3).** Do HEIC/AVIF (and JPEG/PNG/WebP) decode inside an isolated process, and does `SharedMemory` cross the boundary on API 29? The answer decides Q9 (HEIC/AVIF accepted as sources only if the sandbox decodes them).

**Method.** `IsoService` (`android:isolatedProcess="true"`, `:mdec`, not exported) and `IsoClient` implement §9.2's protocol: one `bindIsolatedService` instance with a fresh random name per request, the input in a `SharedMemory` region set to `PROT_READ` before it is passed, the output in a second region the main process creates, maps and zero-fills after copying, unbinding after the reply and waiting for the instance's death (`linkToDeath`), a per-request timeout (20 s in the probe). For each source the `iso` probe runs: `DECODE_IMAGE` (`ImageDecoder` over the mapped read-only region, software allocator, target size within 2 048 × 2 048, sRGB); `STRIP_IMAGE` (§8.2 exactly: canonical geometry ladder, sRGB, `setGainmap(null)` on API 34+, alpha on white, `Bitmap.compress(JPEG)` from q 85 down to 60 then a smaller edge, ≤ 1 048 512 B); the same decode in the main process as a control (to tell "the sandbox cannot" from "the platform cannot"); the main process from a `SharedMemory` mapping (control); and the isolated process from a heap copy (to tell a `SharedMemory` limit from an isolated-process limit). Sources (made once on API 35, pushed unchanged to API 29): `orient1.jpg`, `alpha.png` (alpha), `photo.webp` (static, EXIF), `photo.heic` (`HeifWriter`, HEVC, 1 024 × 768), `photo.avif` (`AvifWriter`, AV1, 1 024 × 768), `p3.jpg` (Display P3), `ultrahdr.jpg` (gain map), `big10000.jpg` (10 000 × 10 000, 100 MP, 1 045 309 B). On 2026-10-03 the `heiclog` step repeated the HEIF/AVIF requests on API 35 with the system log captured.

**Results** (`results/api{29,35}/iso.txt`, `results/api35/iso-rerun1003.txt`, `results/api35/heif-logcat.txt`).

| Source | API 29: isolated decode / strip | API 29: main process | API 35: isolated decode / strip | API 35: main process |
|---|---|---|---|---|
| JPEG 600 × 400 | OK 1.4 ms / OK 512 × 336, 3 025 B | OK | OK 3.4 ms / OK 512 × 336, 2 928 B | OK |
| PNG with alpha | OK / OK (composited on white) | OK | OK / OK | OK |
| static WebP | OK / OK | OK | OK / OK | OK |
| Display P3 JPEG | OK, converted to sRGB / OK | OK | OK / OK | OK |
| Ultra HDR JPEG | OK / OK | OK | OK (`hasGainmap = true`) / OK, gain map removed | OK |
| 100 MP JPEG | OK, 2 048 × 2 048 in 284.5 ms (606 ms on 2026-10-03 under heavier host load), `VmHWM` 244–246 MB / OK 2 048 × 2 048, 126 505 B | OK (sampled) | OK in 180.0 ms, `VmHWM` 165 680 kB / OK 2 048 × 2 048, 126 357 B | OK |
| **HEIC** | **fails: no answer until the 20-s timeout kills the instance** (`DeadObjectException` 2026-09-25, "call timeout" 2026-10-03) | **OK** 1 024 × 768 | **fails: `DecodeException` "invalid input"** | **OK** 1 024 × 768 |
| **AVIF** | **fails** (no answer until the timeout) | fails ("invalid input": no AVIF support on API 29) | **fails: "invalid input"** | **OK** 1 024 × 768 |

`SharedMemory` crosses the boundary on API 29 and 35: every decode reads the read-only mapped region, and the main-process control from a `SharedMemory` mapping also works; the heap-copy variant fails exactly where the region variant fails. API 29's HEIF and AVIF requests did not return: the decoder waited until the client's timeout unbound the instance.

**Why** (API 35 system log, 2026-10-03, every HEIF/AVIF request): `servicemanager: Isolated app with UID 99042 requested 'media.player', but the service is not allowed for isolated apps`, `avc: denied { find } for … name=media.player scontext=u:r:isolated_app … tcontext=u:object_r:mediaserver_service`, `ServiceManagerCppClient: Failed to registerForNotifications in waitForService for media.player: … 'SELinux'`, `HeifDecoderImpl: failed to set data source!`. The platform's HEIF/AVIF image path (`HeifDecoderImpl`) decodes through the media server (`media.player`), which the isolated-app SELinux domain may not look up; on API 29 the lookup waits instead of failing. JPEG, PNG and WebP decode in-process (Skia) and work. API 29's log (2026-10-03, `results/api29/heif-logcat.txt`): inside the isolated instance, `ServiceManager: Waiting for service 'media.player' on '/dev/binder'...` once a second, then `Service media.player didn't start. Returning NULL`, again and again: the lookup is not refused but never answered, so the request hangs until the client's timeout kills the instance.

**Verdict: CORRECTS** the design's open option (the C.3 fallback applies): HEIC/HEIF and AVIF can never be decoded in GHOST's sandbox on API 29 or 35, by platform policy, so under D17 and Q9 they are refused as sources. `SharedMemory` across the boundary is confirmed on API 29.

**Normative correction (S0-4).**
1. §6.1 "Image sources accepted": "JPEG, PNG and static WebP. HEIC/HEIF and AVIF are refused before decoding (`sniff` → `UNSUPPORTED`, `sendMedia` → `UNSUPPORTED_SOURCE`): the platform decodes them through the media server, which an isolated process may not reach (S0 V-M5: `servicemanager` refuses `media.player` to isolated apps; API 29 blocks until the request's timeout, API 35 fails at once), and decoding them in the main process is what D17 forbids."
2. §1.3 row "RAW/DNG, HEIC and AVIF on the wire": "refused on the wire and as sources (V-M5, Q9's fallback)"; §9.1 row "Picked source image": the magic-byte allowlist is JPEG, PNG, WebP (static).
3. §15.7: the HEIC/AVIF row of the corpus becomes a refusal test (a HEIC and an AVIF source produce `UNSUPPORTED_SOURCE` and no sandbox request).
4. Q9 is answered by measurement (refused); a new owner question replaces it (S0 Q-S1): accept that photos a phone stores as HEIC cannot be sent (the picker shows them; GHOST refuses them with a message), or relax D17 for HEIC sources only (a main-process `ImageDecoder` on a file the user picked: the CVE-2023-4863/LANDFALL class of risk, for the user's own files). Default: refuse.
5. §9.2 "Unknowns (S0)": strike the HEIF/AVIF item; record "an isolated process cannot use any decoder that goes through `media.player` (HEIF, AVIF); video is decoded by `MediaCodec` in the main process's client, never in `:mdec`".

---

## 6. V-M6: what `Bitmap.compress(JPEG)` writes, and the gain map

**Question (C.3).** Does `Bitmap.compress(JPEG)` emit a baseline `SOF0`, and with the gain map removed, no trailing image (§8.2: the canonicaliser drops APPn; a trailer fails the send)?

**Method.** The `compress` probe compresses one 600 × 400 test bitmap with `Bitmap.compress(JPEG)` in every configuration `STRIP_IMAGE` can meet: sRGB `ARGB_8888` at q 85, 60 and 100, `RGB_565`, Display P3, `RGBA_F16` linear extended sRGB, a bitmap decoded from the canary-bearing EXIF source, and on API 34+ a bitmap given a gain map (`setGainmap`), the same with `setGainmap(null)`, and the Ultra HDR source decoded by `ImageDecoder` (with and without an sRGB target colour space, with and without `setGainmap(null)`). The outputs, and every `STRIP_IMAGE` output of V-M4/V-M5, are pulled and walked by `mediatool jpeg` (every marker, its length, the bytes after `EOI`) and passed through the reference canonicaliser `mediatool canon` (`rust/src/jpeg.rs::canonicalize`, §8.2's `jpegCanonicalize`: drops APP0–APP15 and COM, keeps SOI, 8-bit DQT, SOF0 with 1 or 3 components, DHT, DRI, SOS with its data, RSTn, EOI; refuses everything else, fill bytes and any byte after `EOI`); the canonical output is canonicalised again (fixed point). ExifTool 13.55 reads every raw and canonical output (`scripts/exif-oracle.sh`, T43's reading: every tag outside a structural allowlist is listed, and the planted canaries are searched in ASCII and UTF-16). API 29 and 35.

**Results** (`results/api{29,35}/compress.txt`, `jpeg-markers.txt`, `exif-oracle-images.txt`; API 35 re-run on 2026-10-03: identical output sizes).
- **Every output is baseline:** `SOI`, `APP0` JFIF (18 B), `APP2` `ICC_PROFILE`, two 8-bit `DQT`, **`SOF0`** (8-bit, 3 components, 4:2:0), four `DHT`, one `SOS`, the entropy-coded data with no restart markers, `EOI`. No `SOF2` (progressive), no `COM`, no `DRI`, no fill bytes, in all 26 (API 35) and 21 (API 29) outputs (the two empty HEIC/AVIF strip results of V-M5 aside).
- **The ICC profile is always written**, even for sRGB: 474 B on API 35 and 554 B on API 29 for sRGB (also for `RGB_565`); Display P3 538 B and extended linear sRGB 506 B on API 35 (API 29 writes 554 B for all three). The canonicaliser drops `APP0` and `APP2` (492 B on API 35, 572 B on API 29) and its output is a fixed point. A canonical file has no colour profile, so a viewer assumes sRGB: STRIP's conversion to sRGB before compressing (§8.2) is what keeps the colours right.
- **The gain map (API 34+):** a bitmap carrying a gain map compresses to an Ultra HDR file: `APP1` Exif (54 B), `APP2` `MPF` (90 B), `APP1` XMP (925 B, the `hdrgm` description), `APP2` ICC, `APP2` ISO 21496-1 (36 B) and, after `EOI`, **a second JPEG of 982–995 B (the gain map)**. The canonicaliser refuses it (`NON_CANONICAL`: bytes after `EOI`), so the send would fail. Decoding to an sRGB target colour space does **not** remove the gain map (same 6 881 B output); **`setGainmap(null)` does**: the output is again `APP0` + `APP2` ICC + baseline, nothing after `EOI`. `STRIP_IMAGE` as §8.2 writes it (it calls `setGainmap(null)` on API 34+) produced no trailer for the Ultra HDR source on API 35; API 29 has no gain-map support and decodes the same source as SDR.
- **No metadata survives:** ExifTool finds **0 tags outside the structural allowlist and 0 canaries in every canonical output** (15 files on API 35, 14 on API 29); the raw STRIP outputs show 29 tags, all from the JFIF and ICC segments the canonicaliser drops. The canary-bearing source (49 tags outside the allowlist: Make, Model, Software, serial, unique id, dates, GPS) leaves none in its STRIP output.
- Platform dependence: compressing the same pixels gives byte-identical canonical files on API 29 and 35 (sRGB at q 60, 85, 100, `RGB_565`, the EXIF source); STRIP outputs of the same source differ by up to about 3 % in length between the two API levels (the decoder's scaling differs; `photo.webp` and `p3.jpg` gave identical files), so a golden of a STRIP output is per API level.

**Verdict: CONFIRMS** the design on API 29 and 35: the encoder writes baseline `SOF0`; with `setGainmap(null)` nothing follows `EOI`; the APPn the platform always adds (JFIF, ICC) are what the canonicaliser drops. Two facts the design does not state are worth recording (below); neither changes it.

**Normative correction.** None. Precisions for §8.2 (optional, no behaviour change): "`Bitmap.compress(JPEG)` always writes `APP0` JFIF and an `APP2` ICC profile (also for sRGB: 474 B on API 35, 554 B on API 29); the canonicaliser drops them, so the canonical file carries no profile and STRIP's sRGB conversion is required. Converting to sRGB does not drop a gain map; only `setGainmap(null)` does (S0 V-M6: otherwise 982–995 B follow `EOI` and the send fails `NON_CANONICAL`)." §15.7's image goldens are per API level (STRIP outputs differ across levels).

---

## 7. V-M7: what Media3 1.11.1 brings into the app (native code, transitive artifacts, size)

**Question (C.3).** The Media3 1.11.1 modules bring no `.so`; the transitive set is Guava, `failureaccess` and nothing else outside `androidx`; what is the R8 size delta?

**Method.** `android/r8probe` is a minimal app built exactly like `ghost/android`'s `:app` release (AGP 9.4.0, `isMinifyEnabled`, `isShrinkResources`, `proguard-android-optimize.txt`, min SDK 29, target 37) in two flavours: `base` (no Media3) and `media`, whose single code path uses Media3 the way §8.3 and §10.2 do (an `ExoPlayer` built with a memory `DataSource` and a `FragmentedMp4Extractor`-only factory with `FLAG_READ_MFRA_FOR_SEEK_MAP`, a 5–15 s / 8 MiB load control, diagnostics off, `Log.LOG_LEVEL_OFF`; a `Transformer` with `DefaultEncoderFactory` and requested settings, a `ContentDataSource`-only asset loader with a refusing `BitmapLoader`, `Presentation`, `FrameDropEffect`, `SonicAudioProcessor`, `ChannelMixingAudioProcessor`, tone-mapping, a `FragmentedMp4Muxer` wrapper as muxer factory). Its dependencies are `media3-transformer`, `-exoplayer`, `-muxer`, `-effect`, `-common` 1.11.1, resolved from Google Maven / Maven Central. Commands: `./gradlew --no-daemon :r8probe:assembleBaseRelease :r8probe:assembleMediaRelease` and `:r8probe:dependencies --configuration mediaReleaseRuntimeClasspath`; `unzip -l` of both APKs; R8's `mapping.txt`; the Gradle module metadata of `media3-common` 1.11.1 in the Gradle cache.

**Results** (`results/r8probe-media-runtime-classpath.txt`, `r8probe-media-dependency-tree.txt`, `r8probe-media-kept-classes.txt`).
- **Native code: none.** Neither APK has a `lib/` entry (`unzip -l`: 13 and 30 entries, no `.so`). `apk-native-libs.sh`'s allowlist needs no line for Media3.
- **Size:** base 16 454 B (`classes.dex` 1 224 B), media 1 263 831 B (`classes.dex` 1 223 200 B; 1 092 classes in the dex, 577 top-level classes in R8's mapping): **+1 247 377 B** for the design's use of Media3 in an otherwise empty app, unsigned. The real delta in `:app` is smaller by whatever it already ships (Kotlin, coroutines, AndroidX annotation and concurrent-futures are already there).
- **The runtime classpath has more than Guava and `failureaccess`.** Beyond `androidx.media3:*` and Kotlin, the resolved `mediaReleaseRuntimeClasspath` holds: `com.google.guava:guava` 33.3.1-android, `com.google.guava:failureaccess` 1.0.2, `com.google.guava:listenablefuture` 9999.0-empty, **`com.google.code.findbugs:jsr305` 3.0.2, `org.checkerframework:checker-qual` 3.43.0, `com.google.errorprone:error_prone_annotations` 2.28.0, `com.google.j2objc:j2objc-annotations` 3.0.0, `org.jetbrains.kotlinx:kotlinx-coroutines-guava` 1.9.0** (with `kotlinx-coroutines-core` 1.9.0 and its BOM), **`androidx.exifinterface:exifinterface` 1.3.6**, `androidx.concurrent:concurrent-futures` 1.2.0 and **`androidx.media3:media3-database` 1.11.1**.
- Why the four annotation artifacts arrive although `media3-common` excludes them: `media3-common`'s module metadata does exclude `j2objc-annotations`, `checker-compat-qual`, `jsr305`, `animal-sniffer-annotations`, `checker-qual` and `error_prone_annotations` on its edge to Guava (the design's §16.3 reads the POM correctly), but `media3-effect` 1.11.1 depends on `kotlinx-coroutines-guava` 1.9.0, which depends on `guava` 31.0.1-jre **without** exclusions (resolved up to 33.3.1-android), and a Gradle exclude applies only to the edge that declares it. `media3-database` is a hard dependency of `media3-datasource` and `media3-exoplayer`; `exifinterface` of `media3-datasource` and `media3-exoplayer`.
- Licences (their POMs): `jsr305` "The Apache Software License, Version 2.0", `checker-qual` "The MIT License", `error_prone_annotations` "Apache 2.0", `j2objc-annotations` "Apache License, Version 2.0", `kotlinx-coroutines-guava` "The Apache Software License, Version 2.0", `exifinterface` Apache-2.0, Guava and `failureaccess` Apache-2.0 (through `guava-parent`). All are on `deny.toml`'s and ADR-37's permissive side; none is copyleft.
- Against `ghost/scripts/gates/gradle-license-allowlist.txt` (the shipped app's set today), the lines the media flavour would add are: the ten `androidx.media3:media3-{common,container,database,datasource,decoder,effect,exoplayer,extractor,muxer,transformer}`, `androidx.exifinterface:exifinterface`, `com.google.guava:guava`, `com.google.guava:failureaccess`, `com.google.code.findbugs:jsr305`, `org.checkerframework:checker-qual`, `com.google.errorprone:error_prone_annotations`, `com.google.j2objc:j2objc-annotations`, `org.jetbrains.kotlinx:kotlinx-coroutines-guava` (`concurrent-futures`, `kotlinx-coroutines-core-jvm`, `listenablefuture` and `org.jetbrains:annotations` are already listed). R8 then keeps 170 Guava classes and 9 `androidx.exifinterface.media` classes and drops `kotlinx.coroutines.guava` and every `media3.database` class (the mapping has none).

**Verdict: CORRECTS** the design: no native library (confirmed), but the third-party set is eight artifacts, not two, and `media3-database` is a Media3 module G-M2 does not allow.

**Normative correction (S0-5).**
1. §16.3, dependency table: replace the Guava and `failureaccess` rows' scope by one row "Media3's transitive runtime set (resolved in S0, V-M7): `com.google.guava:guava` 33.3.1-android, `failureaccess` 1.0.2, `jsr305` 3.0.2, `checker-qual` 3.43.0, `error_prone_annotations` 2.28.0, `j2objc-annotations` 3.0.0 (the last four arrive through `media3-effect` → `kotlinx-coroutines-guava` 1.9.0 → Guava, an edge without Media3's exclusions), `kotlinx-coroutines-guava` 1.9.0, `androidx.exifinterface:exifinterface` 1.3.6; all Apache-2.0 except `checker-qual` (MIT); no native code", and change the `exifinterface` row from "conditional" to "always present (a dependency of `media3-datasource` and `media3-exoplayer`); GHOST code still never references it outside `org.ghost.media.sandbox` (G-M3)".
2. §16.1 G-L2: the allowlist gains the lines of the list above (one ADR-06 review each); alternatively `:media`'s Gradle file excludes the four annotation-only artifacts globally (they are compile-time annotations; R8 removes them), which S1 decides by building `:app` both ways (owner question Q-S5; the lines needed are then fewer). Q28 is widened to this set.
3. §16.1 G-M2: the allowed Media3 artifacts gain `media3-database` (a hard transitive dependency; its `StandaloneDatabaseProvider` is a SQLite writer used by caches and downloads); G-M1's sink list gains `StandaloneDatabaseProvider` and `DatabaseProvider`, so no GHOST code can instantiate it.
4. §16.3: "R8 release delta for the design's use of Media3 in an empty app: +1 247 377 B (S0, V-M7); no `.so`".

---

## 8. V-M8: `aead-stream` 0.6.0 as the dev oracle; the format reference and its vectors

**Question (C.3).** Does `aead-stream` 0.6.0 work as a differential oracle beside `chacha20poly1305` 0.11.0 (`aead` 0.6.1), so that the chunk layer of §3.3 can be checked against code GHOST did not write (`cargo tree -e dev`)? The task's wider question is answered here too: is the format of §3–§4 implementable exactly as written, and do two independent implementations agree on its vectors?

**Method.** `rust/` is the crate `ghost-media-spike` with its own `[workspace]` and lock file. Its normal dependencies are the product pins (`chacha20poly1305` =0.11.0 with `default-features = false`, `hkdf` =0.13.0, `hmac` =0.13.0, `sha2` =0.11.0); `aead-stream` =0.6.0 is a dev-dependency only.
1. `src/format.rs` implements §3.1–§3.7, §4.1 and §4.2 from the design text alone: derivations, nonce and `AD_c`, the sealer with its one-chunk lookahead and index registry, the manifest codec with every §3.5 rule (zero preview pad, zero tail, distinct hashes, the geometry of D29, `content_len` against the class), the descriptor codec (R-D3), `key_env` and its binding, the reader (`readerOpen`/`readerChunk` checks in the §13.2 order), `op_id`, Padmé.
2. `tests/oracle.rs`: for each of the three vector objects, every chunk the sealer produced must equal `StreamBE32::<ChaCha20Poly1305>::encrypt(i, last, {msg, aad: AD_c})` with the 7-byte zero prefix; the stateful `EncryptorBE32` (`encrypt_next` … `encrypt_last`) must reproduce the whole ciphertext; `DecryptorBE32` must open it, and must refuse the first chunk presented as the last one. The RFC 8439 §2.8.2 AEAD vector and the RFC 5869 A.1 HKDF vector check the two primitives with values neither implementation controls.
3. `tests/rules.rs`: the §3.6 class table and overheads, Padmé's class counts, the manifest's spare space, the §3.8 integrity exponent, the sealer discipline of §3.7, and the §3.4 attack table as typed codes.
4. `src/vectors.rs` writes `vectors/media_object.txt` (the future `protocol/test-vectors/media_object.txt`): constants, the class table and every boundary, three objects (an image of class 0, a video filling class 0 exactly, a view-once video one byte into class 1) with derivations, nonces, `AD_c`, every fragment hash, the manifest plaintext head and digest, the manifest hash, the descriptor, `key_env` for both roles and two `op_id`s. `tests/vectors.rs` fails on any difference and opens every case.
5. `jvm/MediaVectors.java` replays the file with code that shares nothing with the Rust side: SunJCE's `ChaCha20-Poly1305`, an HKDF written from RFC 5869 over `HmacSHA256`, its own encoders of the manifest, descriptor, `key_env` and `op_id`, and five negative cases per object of its own (a flipped chunk byte, chunk 0 opened as last, the manifest under another `object_id`, `key_env_out` under the inbound binding, another `K_f`'s commitment).

**Commands** (from `ghost/spikes/media-s0`, `CARGO_TARGET_DIR` outside `D:`): `cd rust && cargo test --release --locked -- --nocapture`; `cargo tree --locked -e normal,dev`; `java jvm/MediaVectors.java rust/vectors/media_object.txt`.

**Results (2026-10-03, re-run of the 2026-09-25 session).**
- `cargo test`: 11 tests in 3 targets, all pass (oracle 3, rules 6, vectors 2).
- Graph: `aead-stream v0.6.0 → aead v0.6.1 (*)`, the same `aead` 0.6.1 as `chacha20poly1305 v0.11.0` (with `chacha20` 0.10.2, `poly1305` 0.9.1, `cipher` 0.5.2); `cargo tree -e dev -d` prints nothing (no duplicated package). The lock checksums of `aead`, `chacha20`, `chacha20poly1305` and `poly1305` are byte-identical to `ghost/Cargo.lock`'s; `aead-stream` 0.6.0's is `a901e5bc…0bac`.
- Oracle: every chunk of the three objects equals `StreamBE32`'s output byte for byte, the stateful encryptor reproduces each object, the decryptor opens them and refuses a non-final chunk opened as final. The layout claim of R-O2 ("exactly `aead-stream` 0.6.0's `StreamBE32`") holds.
- `rules.rs` numbers, all as the design states: worst overhead just above a class boundary **58.34 %** (class 2 → 3; the design says "below 59 %"); the mean `3 ln 1.5 − 1` = 21.64 %; Padmé over byte lengths rounded to whole chunks: **111** classes above class 0 (design "about 110"), over fragment counts: **54** (design "about 55"); manifest: hashes end at 58 534 of 65 488, **6 954 B** spare; a chunk is `L′ + 1 = 16 384 = 2^14` blocks, forgery bound `2^−89` (§3.8); 256 sampled single-bit flips → `HASH_MISMATCH`, a flip under a re-hashed manifest → `NOT_OPEN` (tag), swapped fragments → `HASH_MISMATCH`, a chunk swap with a re-sealed manifest → `NOT_OPEN` (index in the nonce), the last chunk re-sealed without the last flag → `NOT_OPEN`, a chunk of another `object_id` or of another `kind` → `NOT_OPEN`, a duplicated hash → `NON_CANONICAL`, another `K_f` → `COMMIT_MISMATCH`, a flipped manifest byte → `NOT_OPEN`, descriptor flags or class unlike the manifest → `NON_CANONICAL`, a non-zero content pad byte → `NON_CANONICAL`, a non-zero preview pad, an image above class 0, a view-once object with a preview, a long edge off the ladder and a video over `VIDEO_MAX_MS` → `NON_CANONICAL`, index `n` → `INDEX_RANGE`. The sealer holds a full chunk until the next byte arrives (0 fragments after exactly `CHUNK_PT` bytes, 4 after one more), refuses a second seal of one index (`INDEX_REUSED`), produces identical fragments and manifest for input pieces of 7 B … `CHUNK_PT + 1` B, and its `(SHA-256(K_p), nonce)` log repeats when a preparation is resumed under the same key with different plaintext (the §3.7 point 5 registry catches MC-M1).
- JDK replay (JDK 17.0.20.1): **145 values compared, 145 equal; 15 negative cases, 15 refused.** Vector file: 217 lines, SHA-256 `e0ea7a82…0ed5`.

**Found while doing it (two defects of the evidence tooling, one ambiguity of the design).**
1. *Fixed in the spike.* The generator of 2026-09-25 wrapped `key_env_out` and `key_env_in` under the same state key **and the same fixed nonce**: two seals under one `(key, nonce)`, which a vector set must never model (the first 32 bytes of both ciphertexts were equal). `wrap_nonce_in` now differs from `wrap_nonce_out`, `tests/vectors.rs` asserts that the two prefixes differ and that `key_env_in` opens under the inbound binding, the file was regenerated, and the JDK replay was updated and passes.
2. *Not done by the spike.* §3.9 asks for one negative case per row of §3.4 and per rule of §3.5 **in the vector file**. The spike holds them as Rust tests (`rules.rs`) and as the JDK program's own five cases per object, not as data both implementations replay. S1 must add them to the file (no design change).
3. *Design ambiguity.* `"ghost/v1/media/manifest"` is both the HKDF `info` of `K_m` (§3.2) and the prefix of `AD_m` (§3.5). Among the three HKDF labels no label is a prefix of another (the §3.2 rule holds), but a label test over every string of the crate (HKDF labels, AEAD associated-data prefixes, the `op_id` label) finds this one duplicate. It is harmless cryptographically (an HKDF `info` and an AEAD associated datum are inputs of different primitives under different keys), but the rule as written does not say which set it ranges over, and a strict `DerivationLabelsTest` over all strings would fail.

**Verdict: CONFIRMS** the design (the oracle works as planned; no fallback needed), with the label clarification of S0-6.

**Normative correction (S0-6).**
1. §3.2, "Labels" bullet, replace the sentence on the prefix test by: "a prefix test asserts that no HKDF `info` label is a prefix of another (the `DerivationLabelsTest` rule); the associated-data prefixes of §3.3 and §3.5 and the `op_id` label of §6.4 are a second set with the same rule. `"ghost/v1/media/manifest"` is deliberately in both sets (the `info` of `K_m` and the prefix of `AD_m`); the test allows exactly that pair (S0 V-M8)."
2. §3.9: "the vector file carries the negative cases as data (each with the typed code it must produce); the generator never seals two vectors under one `(key, nonce)` pair: the two `key_env` roles use different fixed nonces."
3. §16.3, `aead-stream` row: status "dev graph only; confirmed in S0 (V-M8): resolves with the product's `aead` 0.6.1, no duplicated package".

---

## 9. V-M9: seal and open throughput, and the memory of the largest object

**Question (C.3).** Do seal and open reach ≥ 100 MB/s on the reference mid-range phone (the soft `poly1305` backend has no NEON)? The task adds: the time and memory budgets of the largest objects on the emulator.

**Method.** `mediatool bench` seals a 50 MiB object (52 428 800 B, class 10: 804 fragments + 1 manifest, 52 756 480 B on each relay) through the reference sealer (`format::Sealer`, the lookahead of §3.7) in 1 MiB appends, keeping every fragment, then opens it chunk by chunk (hashes, tag, pad) with `Reader`; `bench-stream` seals the same object dropping each fragment after hashing it, as the product writes fragments to files at once, and reports `VmHWM` before and after. Three runs each on the host (Windows, x86_64) and, as an x86_64 Android binary (`cargo ndk -t x86_64`), on each emulator. The `bench` probe times the alternative D8 rejected, JCA `ChaCha20/Poly1305/NoPadding` (Conscrypt, "AndroidOpenSSL"), over the same 201 chunks in the app. The 100 MP decode of V-M5 and the 160-s transcodes of V-M22 give the other two large budgets.

**Results.**

| | Seal 50 MiB (keeping fragments) | Seal 50 MiB (streaming) | Open + hash + verify | Memory |
|---|---|---|---|---|
| host, Core Ultra 9 275HX under 97–100 % load (2026-10-03; 2026-09-25 in brackets) | 122.7 ms = **427 MB/s** (128–155 ms) | 151 ms = **347 MB/s** (163–178 ms) | 67.4 ms = **778 MB/s** (76–86 ms) | — |
| API 35 emulator, x86_64 binary, 3 runs (2026-09-25) | 214–228 ms = **230–245 MB/s** | 185–193 ms = **272–283 MB/s** | 154–169 ms = **311–340 MB/s** | `VmHWM` 107.6 MB keeping fragments; **4.9 MB** streaming (3.5 MB before) |
| API 29 emulator, x86_64 binary, 3 runs (2026-10-03) | 188–338 ms = **155–279 MB/s** | 153–207 ms = **253–343 MB/s** | 183–231 ms = **227–287 MB/s** | `VmHWM` 115–117 MB keeping fragments; **7.0 → 7.4 MB** streaming |
| JCA ChaCha20-Poly1305 in the app, API 35 | 0.550 s = **95.8 MB/s** (encryption only, no hashing) | | | app `VmHWM` 232 MB |
| JCA ChaCha20-Poly1305 in the app, API 29 (2026-10-03) | 0.337 s = **156.3 MB/s** | | | app `VmHWM` 234 MB |

Other budgets measured in this slice: decoding the largest admissible image source (10 000 × 10 000, 100 MP) inside a fresh isolated instance with a 2 048-px target takes 180–606 ms with the instance's `VmHWM` at 166–246 MB (V-M5; the spread is host load); transcoding a 160-s source takes 152–249 s on the API 35 emulator and 144–332 s on API 29, with the app at 209–247 MB `VmHWM` (V-M22); the API 35 emulator grants the app a 192 MB heap (`memoryClass`), API 29's 576 MB (`results/api{29,35}/env.txt`).

What the numbers say: sealing and opening are two to three orders of magnitude faster than Tor moves the bytes (a few Mbit/s), streaming costs about 1.4 MB of memory (one held chunk and the hash list), and the Rust path is as fast as JCA or up to 2.9 times faster on the same emulators (JCA encrypts only; the Rust figures include hashing every fragment), so D8's "acceptable anyway" holds on x86_64 with room to spare. **None of this is an ARM number**: the emulators are x86_64, where `chacha20`, `poly1305` and `sha2` pick their x86_64 SIMD backends at run time; on arm64 `chacha20` has a NEON backend, `poly1305` 0.9.1 only the soft one, and `sha2` uses the ARMv8 SHA extensions where present. The reference phone remains the only valid measurement (S0b).

**Verdict: INCONCLUSIVE** for the question as asked (needs the reference mid-range phone, S0b); the x86_64 figures are 2–4 × above the threshold and the memory budget of the largest object is confirmed (streaming sealer ≈ 1.4 MB).

**Normative correction.** None. §13.1's performance row may cite "x86_64 emulator: seal 230–283 MB/s, open 311–340 MB/s, 50 MiB object streamed in ≈ 1.4 MB of memory (S0 V-M9); arm64: S0b".

---

## 10. V-M10: transfer times per class over live Tor

**Question (C.3).** What are the transfer times of each size class over live Tor (the `live-tor` harness against one onion relay)? The design makes no claim from them; they size Q29 and the media lane's budgets (§5.5).

**Not run.** The check needs a GHOST relay reachable as an onion service (staging relays are an owner action, S0b; R-M15). Nothing of the kind exists for this workstation, and timing a public Tor path to some other server would measure a different path from the design's (three relays of one set, a client per RPC, F-M2). The design's own estimates (§5.4, §5.5, Q29: ≈ 24 min to fetch 25 MB in the foreground with today's budgets; classes 9–10 needing 23–64 minutes of foreground upload) stay estimates.

**Verdict: INCONCLUSIVE (not run: needs staging relays).**

**Normative correction.** None beyond keeping V-M10 in S0b. One input for it from this slice: the upload is not the only long step for large classes. A 160-s source took 2 min 34 s to transcode on the API 35 emulator (V-M22), and no fragment is stored before `MEDIA-COMMIT`, which follows the whole transcode and `sealFinish` (§6.2, §6.3); §6.4's deadline arithmetic (Q29) should count the preparation time too, measured on the reference phones.

---

## 11. V-M11: reading the picked stream without an app-side copy

**Question (C.3).** Are the picker's and SAF's streams read without an app-side copy (`FileObserver`)? GHOST never copies; the check records that the platform does not do it on GHOST's behalf.

**Method.** The `pick` probe of V-M21: before launching the picker it takes an inventory (path, size, `lastModified`) of every directory the app can write without a permission and attaches a recursive `FileObserver` (create, modify, close-write, move, delete, attribute) to each; `PickActivity` then reads the returned URI with `ContentResolver.openInputStream` straight into memory, as §6.1 prescribes, and hashes it; the probe stops the watch and diffs the inventory. On API 35 the URI comes from the photo picker (`ACTION_PICK_IMAGES`), on API 29 from DocumentsUI (`ACTION_OPEN_DOCUMENT`, the SAF path `PickVisualMedia` falls back to).

**Results** (`results/api35/vm21-2026-10-03/pick.txt`, `results/api35/vm21/pick.txt`, `results/api29/vm21/pick.txt`, `results/api29/vm21-first/pick.txt`).

| | URI returned | Bytes read; equal to the pushed file? | Grant flags | `FileObserver` events | Inventory changes |
|---|---|---|---|---|---|
| API 35, 2026-10-03 | `content://media/picker/0/com.android.providers.media.photopicker/media/1000000018` | 4 341; **no**: same length, another SHA-256 (V-M21) | `0x41` (read, persistable) | **0** | **0** |
| API 35, 2026-09-25 | the same URI | 4 341; no (the same other SHA-256) | `0x41` | 1 (`IN_IGNORED`, the watch's own removal at `stopWatching`) | **0** |
| API 35, 2026-10-04 | `…/media/1000000019` (the same picture, pushed under another name) | 4 341; no: the same SHA-256 again, the GPS fields zeroed (V-M21) | `0x41` | 1 (`IN_IGNORED`) | **0** |
| API 29, 2026-10-04 (two picks) | `content://com.android.providers.media.documents/document/image%3A14` and `…image%3A15` | 4 341 and 4 264; yes, byte for byte | **`0x43` (read, write, persistable)** | **0** | **0** |

**Verdict: CONFIRMS** on API 29 and 35: reading the picked stream writes nothing into the app's directories. (What the *system* writes about a pick, outside the app, is V-M21.)

**Normative correction (S0-7, precision).** §6.1 "No copy", append: "On API 29 DocumentsUI returns a **read and write** grant (`0x43`) on the user's own file; GHOST opens it read-only (`openInputStream`, never `openOutputStream` or mode `"w"`) and never calls `takePersistableUriPermission` (S0 V-M11: the photo picker grants read only, `0x41`)." The read-only use can join G-M1's source rule (no `openOutputStream`/`openFileDescriptor(…, "w…")` on a picked URI).

---

## 12. V-M12: SEI payload types and AAC elements of the encoders (emulator half)

**Question (C.3).** Which SEI payload types do the reference encoders emit, and does their AAC output contain DSE or non-zero FIL elements? The check is S0b (the gate devices); S0a covers the emulators' software encoders.

**Method.** (1) Every H.264 access unit that `GhostMuxer` receives is split into NAL units and every SEI NAL's payload types are counted before the SEI filter acts (the filter keeps payload types 0, 1 and 6 and drops the others, §8.3); `mediatool mp4` counts NAL and SEI payload types and parses the SPS (profile, level, VUI) of every output. (2) For AAC, `mediatool` reads the first syntactic element of every raw data block (SCE, CPE, CCE, LFE, DSE, PCE, FIL, END); it does **not** walk the elements after the first, so a FIL or DSE following the channel element is not seen. (3) The sources carry planted canaries in both channels: an SEI `user_data_unregistered` (type 5) NAL with a canary before every frame and a DSE with a canary at the start of every AAC frame (`SourceMaker`), so the transmux control shows that the measurement sees them. (4) Each emulator's own encoders with no request beyond size, rate and bitrate: the `encoders` step makes `t10_plain.mp4` with the platform `MediaCodec` encoders and walks it.

**Results** (`results/api35/transcode-save.txt`, `transcode-fixes.txt`, `mp4-report.txt`, `mp4-sources-report.txt`, `nalcmp-canary.txt`; `results/api29/encoders-mp4.txt`; API 29 transcodes: §1).
- **API 35, `c2.android.avc.encoder`** (every encoded output: the 26 exports of `transcode-save.txt` and `transcode-fixes.txt` that were not transmuxed): NAL types 1 and 5 only, **no SEI NAL at all**, so the filter had nothing to drop; SPS Baseline (66), level 4.1, `pic_order_cnt_type` 2, one reference frame, VUI present with the colour description of V-M17.
- **API 29, `OMX.google.h264.encoder`** (`t10_plain.mp4`, 10 s): NAL types 1 and 5, **no SEI**; Baseline, level 4.1, VUI without a colour description; **one IDR frame in 300** although a 2-s key-frame interval was requested (`KEY_I_FRAME_INTERVAL` = 2); 5.78 Mbit/s for a 2 Mbit/s request on the `mixed` content (+189 %). It refuses a configuration with `KEY_PROFILE` or the colour keys (`configureCodec returning error -38`).
- **API 29 through Transformer** (the GLES 3 boot of §1, the 48 encoded exports of `results/api29gles/transcode-vm1-observe.txt`, `transcode-save.txt` and `transcode-fixes.txt`): the same encoder, NAL types 1 and 5, no SEI, and **one IDR in every 6–12-s export** although Transformer requested its default 1-s interval; the 160-s exports of V-M22 had five each (on average one every 32 s).
- **AAC** (`c2.android.aac.encoder` on API 35, `OMX.google.aac.encoder` on API 29): the first element of every raw data block is a **CPE** (stereo) in every output (562 of 562 blocks in the 12-s outputs on API 35, 563 of 563 and 282 of 282 on API 29, 469 of 469 in API 29's own source). Whether a FIL or DSE follows it was not measured.
- **The control works:** the `PLAIN_DEFAULTS` transmux passes the source's SEI type 5 NALs (360 per output, all dropped by the filter: `seiNalsDropped=360 kept=0`) and the source's AAC DSE canary through (562 raw copies of `GHOSTCANARYS0` in the output's audio); every forced re-encode removes both (0 canaries, V-M17).

**Verdict: INCONCLUSIVE** for the question as asked (the reference devices are S0b). Emulator half: the software encoders of API 29 and 35 emit no SEI at all and start every AAC block with a CPE; the SEI filter removes what a transmux would carry, and forced encoding removes DSE canaries.

**Normative correction (S0-8).** No change to the design text; C.3's V-M12 row (S0b) gains two requirements for its tooling: "the AAC element dump walks every element of each `raw_data_block()` up to `ID_END` (S0's tool read only the first, CPE in every block) and reports DSE and FIL elements with their lengths and whether a FIL's payload is non-zero" and "the NAL dump records the key-frame spacing of each encoder (API 29's `OMX.google.h264.encoder` ignored the requested interval: one IDR in a 10-s source, on average one every 32 s over 160 s; a device encoder that does the same makes V-M2's fragments as long as its own spacing, §2)".

---

## 13. V-M13: platform diagnostics with `setUsePlatformDiagnostics(false)`

**Question (C.3).** With platform diagnostics off, is there no MediaMetrics playback session (`dumpsys media.metrics`)? The design declares `MediaCodec`'s own metrics (L9-M8) and claims that the ExoPlayer and Transformer flag stops the rest (§10.2).

**Method.** The `play` probe plays the V-M2 golden (`match720p30__DESIGN_tfdt_mfra.mp4`) to the end through ExoPlayer with the fMP4-only extractor, once with `setUsePlatformDiagnostics(false)` and once with `true`; `dumpsys media.metrics` is captured before, between and after (`results/api35/media-metrics-diff.txt`: the entries added by each playback for the probe's UID, entry indices stripped). The 1.11.1 bytecode was read for where the flag acts: `ExoPlayerImpl.<init>`, `ExoPlayerImpl$Api31.registerMediaMetricsListener`, `MediaMetricsListener.create`, `Transformer.setUpMetricsCollection`/`canCollectEditingMetrics`. API 29 has no `MediaMetricsManager` (API 31+).

**Results.**
- **API 35, both playbacks added the same 14 entries**: one `audio.track.N` lifecycle (create, `setPlayerIId`, **`setLogSessionId`**, `setVolume`, start, stop, flush, dtor), one `audiotrack` summary, one `codec` entry for `c2.goldfish.h264.decoder` (resolution, colour format, …) and one for `c2.android.aac.decoder`. With diagnostics **off** the audio track still received a log session id (`logSessionId=NyBpjzkS6_QheDL-`), with diagnostics on another (`Ndc0YA-xqoI--lZQ`). Neither run produced a playback-event entry in this dump (they go to `statsd`, which the dump does not show).
- **Bytecode, 1.11.1:** on API 31+, `ExoPlayerImpl.<init>` always calls `ExoPlayerImpl$Api31.registerMediaMetricsListener`, which calls `MediaMetricsListener.create(context)` → `MediaMetricsManager.createPlaybackSession()` and then `PlayerId.setLogSessionId(listener.getLogSessionId())` **unconditionally**; only `addAnalyticsListener(listener)`, which reports playback events, depends on `usePlatformDiagnostics`. R8 keeps `MediaMetricsListener` for that reason (V-M14). The player's `PlayerId` carries that `LogSessionId` to the components Media3 creates; in this dump it appears on the `AudioTrack` record (`setLogSessionId`), while the `codec` records show no session field. For **Transformer** the flag is complete: `setUpMetricsCollection` creates an `EditingSession` only when `canCollectEditingMetrics()`, i.e. `SDK_INT ≥ 35` **and** `usePlatformDiagnostics`.
- **API 29** (2026-10-03, `results/api29/media-metrics-counts.txt`): `media.metrics` exists and each playback added 3 entries whatever the flag: a `codec` entry for `OMX.google.h264.decoder` (with the resolution), an `audiotrack` entry and a `codec` entry for `OMX.google.aac.decoder`, each with the app's UID and PID; no session id anywhere (no `MediaMetricsManager` below API 31, so ExoPlayer creates no session there).

**Verdict: CORRECTS** the design: with diagnostics off, ExoPlayer 1.11.1 still creates a platform `PlaybackSession` on API 31+ and its id reaches the playback's audio-track record; what the flag stops is the reporting of playback events. The C.3 fallback (declared) applies; nothing in Media3's public API turns the session off.

**Normative correction (S0-9).**
1. §10.2, "Declared" bullet, replace the clause on diagnostics by: "`setUsePlatformDiagnostics(false)` stops ExoPlayer's playback-event reports, but on API 31+ ExoPlayer 1.11.1 still creates a `MediaMetricsManager` playback session and puts its `LogSessionId` in the player's `PlayerId` (`ExoPlayerImpl$Api31.registerMediaMetricsListener`; S0 V-M13), so a platform session exists for every playback and its id is attached to the playback's audio-track record (S0, API 35), next to the codec records (codec name, resolution, the app's UID and times) that `MediaCodec` reports anyway. Transformer with the flag off creates no editing session. Both are declared in L9-M8."
2. L9-M8 (and Appendix B.4): add "and, on API 31+, a playback session that ExoPlayer creates whatever the diagnostics flag, whose id is attached to the playback's audio-track record".
3. §16.1 G-M1: no change (the session is created inside Media3; a GHOST source rule cannot remove it).

---

## 14. V-M14: what R8 removes from the release dex

**Question (C.3).** Does R8 remove `SimpleCache`, the `Download*` classes and the HTTP data sources from the release dex, so that a release-dex check can back G-M1?

**Method.** The `media` flavour of V-M7 (R8, `proguard-android-optimize.txt`); a class counts as kept when its original name appears in R8's `mapping.txt` (obfuscated names cannot be searched in the dex). Every class G-M1 or §10.3 names, plus the extractors, image loaders and diagnostics classes that the design's player and transcoder could reach.

**Results** (`results/r8probe-media-kept-classes.txt`).

| Removed by R8 | Kept by R8 |
|---|---|
| `SimpleCache`, `CacheDataSource`, `CacheDataSink`, `CacheWriter`, `DownloadManager`, `DownloadService`, `DownloadHelper`, `HttpEngineDataSource`, `AesCipherDataSource`, `AesCipherDataSink`, `DataSourceInputStream`, `InAppFragmentedMp4Muxer`, `JpegExtractor`, `PngExtractor`, `WebpExtractor`, `FrameExtractor`, `EventLogger`, every `media3.database` class, `kotlinx.coroutines.guava` | **`DefaultDataSource`, `DefaultHttpDataSource`, `UdpDataSource`, `FileDataSource`**, `ContentDataSource`, `AssetDataSource`, `RawResourceDataSource`, **`InAppMp4Muxer`, `DefaultMuxer`**, `Mp4Extractor`, `FragmentedMp4Extractor`, `MatroskaExtractor`, `JpegMotionPhotoExtractor`, `HeifExtractor`, `AvifExtractor`, `BitmapFactoryImageDecoder`, `DataSourceBitmapLoader`, `ExifInterface`, `DefaultVideoFrameProcessor`, **`MediaMetricsListener`**, `DefaultAnalyticsCollector` |

Why they stay, from R8's own `-whyareyoukeeping` report (`./gradlew -PwhyKeeping :r8probe:assembleMediaRelease`, `android/r8probe/why-kept.pro`, 2026-10-03): `DefaultHttpDataSource` is instantiated in `DefaultHttpDataSource$Factory.createDataSource()`, an implementation of `DataSource.Factory.createDataSource()`, which `ProgressiveMediaSource.createPeriod` calls polymorphically from `ExoPlayerImplInternal.doSomeWork()`; `UdpDataSource` and `FileDataSource` are fields of `DefaultDataSource`, reached through `DefaultDataSource.addTransferListener` on the same path; `InAppMp4Muxer` is referenced from `DefaultMuxer.close()` and from `Transformer.setUpMetricsCollection()`; `MediaMetricsListener` is instantiated by `ExoPlayerImpl.<init>` through `ExoPlayerImpl$Api31` (V-M13); `BitmapFactoryImageDecoder` is the `decoder` of `ImageRenderer`, which `ExoPlayerImplInternal.doSomeWork()` renders. The last chain matters beyond R8: with Media3's default renderers factory the player contains an `ImageRenderer` that would decode images with `BitmapFactory` in the main process, so §16.1 G-M3's "the player's renderers factory builds only a `MediaCodec` video and audio renderer" is necessary, not cosmetic.

**Verdict: CORRECTS** the design's assumption. The cache and download classes go, the HTTP, UDP and file data sources, the default MP4 muxer and the platform-diagnostics listener stay in every release that uses the builders as §8.3 and §10.2 do. The fallback named in C.3 applies: those classes stay governed by G-M1's source rule alone, plus the sandbox scan.

**Normative correction (S0-10).**
1. §10.3, first two rows, "Control" column: replace "release-dex check where R8 allows it (V-M14)" by "release-dex check of the classes R8 removes in S0 (V-M14: `SimpleCache`, `CacheDataSource`, `CacheDataSink`, `CacheWriter`, `Download{Manager,Service,Helper}`, `HttpEngineDataSource`, `AesCipherDataSource`/`Sink`, `FrameExtractor`, every `media3.database` class): a release that contains one of them means GHOST code started referencing it. `DefaultDataSource`, `DefaultHttpDataSource`, `UdpDataSource`, `FileDataSource`, `InAppMp4Muxer` and `DefaultMuxer` are always present (the builders' defaults reference them) and are governed by G-M1's source rule and the bytecode rule over GHOST's own classes only".
2. §16.1 G-M3, bytecode rule: add "the release dex legitimately contains Media3's `BitmapFactoryImageDecoder`, `DataSourceBitmapLoader`, `ExifInterface`, `HeifExtractor` and `AvifExtractor` (kept by R8 through the builders' defaults, S0 V-M14); the rule is over GHOST's compiled classes, never over the dex as a whole".
3. T44's verification column: "release-dex check (V-M14)" becomes "release-dex absence check of the S0-measured removable set (V-M14)".

---

## 15. V-M15: `memtagMode` for `:mdec` alone

**Question (C.3).** Can `memtagMode` be set for `:mdec` alone (a manifest probe on an MTE device)? Phase 11 does not enable it (Q21); the check informs Q21.

**Method.** `android/mteprobe` is a manifest only: `android:memtagMode="off"` on `<application>`, a `<processes>` block with `<process/>` (the default process) and `<process android:process=":mdec" android:memtagMode="sync"/>`, and an isolated service in `:mdec`. AAPT2 compiles it (`results/mteprobe-manifest.txt`, the compiled XML tree); each emulator installs it and `dumpsys package` is read; the package is then uninstalled.

**Results** (`results/api{29,35}/mte-install.txt`).
- AAPT2 (AGP 9.4.0, compile SDK 37) accepts the per-process attribute: `memtagMode` = 0 on the application, 2 (`sync`) on the `:mdec` process entry.
- **API 35:** installed; `dumpsys package` lists `processes: org.ghost.spike.mte, org.ghost.spike.mte:mdec` (the per-process entries were parsed) and `PRIVATE_FLAG_ALLOW_NATIVE_HEAP_POINTER_TAGGING`. The x86_64 emulator has no MTE, so nothing shows whether the mode would be applied.
- **API 29:** installed; no `processes` block in `dumpsys package`: the element is unknown to Android 10's parser and ignored (harmless).
- A point the run makes visible: an isolated instance does not run under the process name `…:mdec`. Its name is `<package>:mdec:<service class>:<instance name>` (V-M19 records `org.ghost.spike.media:mdec:org.ghost.spike.media.IsoService:ping_306a…`). Whether a `<process android:process=":mdec">` entry, keyed by process name, applies to such instances is exactly what the MTE device must show.

**Verdict: INCONCLUSIVE** (needs an MTE device, S0b). The manifest form is accepted by the build and parsed by API 35's package manager, and is inert on API 29.

**Normative correction (S0-11).** No change to Phase 11 (Q21 keeps MTE off). C.3's V-M15 row (S0b) gains one requirement: "on the MTE device, read `/proc/<pid>/status` (or the tagged-address control) of a **bound isolated instance** whose name carries the instance suffix, not only of a plain `:mdec` process, since per-process manifest entries are matched by process name (S0 V-M15/V-M19)".

---

## 16. V-M16: `setLastModified(0)` on the app's ciphertext directory

**Question (C.3).** Does `setLastModified(0)` hold on app directories (f2fs, ext4), so that `mtime` carries no time (§10.4)? What else of a file's times and identity remains (L9-M6 declares `ctime`, the birth time and inode adjacency)?

**Method.** The `mtime` probe writes 17 files of 65 536 random bytes with random 16-byte hex names into `noBackupFilesDir/m/` exactly as `CiphertextFiles` would (`FileOutputStream`, `force(true)`, `fsync` of the directory), then for each: `Os.stat` before; `File.setLastModified(0)`; `Os.stat`; then the candidate fix `BasicFileAttributeView.setTimes(EPOCH, EPOCH, null)` (mtime and atime); `Os.stat`. Afterwards a root shell lists `stat -c '%n ino=%i mtime=%y ctime=%z atime=%x'` of the directory. The mount table is recorded by the `env` probe.

**Results.**
- **API 35** (2026-09-25, `results/api35/mtime.txt`, `mtime-stat.txt`): `/data` is **ext4** (`/dev/block/dm-43`, `noatime`). `setLastModified(0)` returned true for all 17 files and **`mtime` became 0**; **`atime` stayed at the creation second** (1790315803; `setLastModified` does not touch it and `noatime` means nothing ever moves it again); `ctime` stayed at the write time, to the millisecond in `stat` (08:56:43.252 … 08:56:43.404, i.e. 8–12 ms apart for consecutive files, so the writing order and pace are readable). `setTimes(0, 0)` set **`mtime` = 0 and `atime` = 0**; `ctime` is stamped by that call too and cannot be set by an app. **Inode numbers were consecutive** (352521 … 352538 for the 17 files, one gap), which groups one object's files exactly as L9-M6 declares.
- **API 29** (2026-10-03, `results/api29/mtime.txt`, `mtime-stat.txt`): `/data` is **ext4** too (`/dev/block/vdc`, `noatime`, `data=ordered`); identical behaviour: `setLastModified(0)` → `mtime` 0, `atime` left at the creation second, `setTimes(0, 0)` → both 0, `ctime` kept (to 10 ms in `stat`), consecutive inode numbers (123525 …).
- **f2fs:** neither emulator image uses it (both `/data` are ext4); the birth time (`crtime`, ext4's and f2fs's `inode_crtime`) was not measured: API 29's toybox 0.8.0 prints `?` for `stat %w`, and a forensic reader of a seized device reads the raw inode anyway. Both remain for the reference phones (S0b).

**Verdict: CORRECTS** the design: `setLastModified(0)` does zero `mtime` on ext4, but it leaves **`atime` at the creation time**, a timestamp the design neither zeroes nor declares; `BasicFileAttributeView.setTimes(EPOCH, EPOCH, null)` zeroes both. `ctime` and inode adjacency are confirmed as declared. f2fs is unmeasured.

**Normative correction (S0-12).**
1. §10.4, second bullet: replace "`setLastModified(0)` after each write so that `mtime` carries no time (V-M16 checks that it holds on f2fs and ext4 app directories)" by "after each write, `Files.getFileAttributeView(path, BasicFileAttributeView::class.java).setTimes(FileTime.fromMillis(0), FileTime.fromMillis(0), null)`, so that `mtime` **and `atime`** carry no time (S0 V-M16 on ext4: `setLastModified(0)` alone leaves `atime` at the creation second, and `/data` is mounted `noatime`, so it would never move again); f2fs is checked on the reference phones (S0b)."
2. §12.4 and L9-M6: "`mtime` = 0 and `atime` = 0; `ctime` to the millisecond as read by `stat` (stamped by the write and by the time-setting call itself; consecutive files of one object 8–12 ms apart on the emulator), the birth time where the file system keeps one, and consecutive inode numbers (17 files → 352521 … 352538 on the emulator) group an object's files and order objects".
3. §15.5 (EP-M) and the sandbox scan: assert `mtime = atime = 0` for every file under `m/`.

---

## 17. V-M17: forced encoding of a source that already matches the output

**Question (C.3).** With the forcing encoder factory and tone-mapping, is a source that already matches the output (H.264 + AAC, ≤ 720p30, SDR, square pixels) re-encoded on API 29, 35 and 37: are both encoder names set, are the output SPS/VUI the device encoder's, and does no source NAL unit or AAC frame survive?

**Method.** The matching source `match720p30.mp4` (1 280 × 720, 30 fps, 12 s, H.264 Baseline at 1.8 Mbit/s, AAC-LC 48 kHz stereo, made by the emulator's own encoders) carries everything a pass-through would reveal: a VUI colour description of BT.601 full range, an SEI `user_data_unregistered` NAL with a canary before every frame, a DSE with a canary in every AAC frame, a location and creation times. It is exported in five configurations: **DESIGN** (§8.3: the forcing wrapper around `DefaultEncoderFactory` with requested settings, `Presentation`, `FrameDropEffect`, the audio processors, `HDR_MODE_TONE_MAP_HDR_TO_SDR_USING_OPEN_GL`), **UNFORCED_EFFECTS** (the same without the wrapper), **PLAIN** (no effects, requested settings, tone-mapping), **PLAIN_KEEP_HDR** (no effects, requested settings, Transformer's default `KEEP_HDR`) and **PLAIN_DEFAULTS** (no effects, no requested settings, `KEEP_HDR`: the control that is allowed to transmux). `ExportResult` gives the encoder names and the per-track `videoConversionProcess`/`audioConversionProcess`; `mediatool mp4` parses each output's SPS and VUI; `mediatool nalcmp` looks for every source NAL unit and AAC frame (≥ 16 B) in the output, whole and as 1 080 / 1 686 sampled 16-byte windows; `mediatool canary` searches the planted strings. The 1.11.1 bytecode was read for when Transformer may skip encoding. A second source, `match720p30_709.mp4`, has no colour description (the colour control), and the DESIGN export was repeated with the wrapper setting `ColorInfo.SDR_BT709_LIMITED` on the encoder's format (the fix under test).

**Results, API 35** (`results/api35/transcode-save.txt`, `transcode-fixes.txt`, `mp4-report.txt`, `nalcmp-canary.txt`).

| Configuration | Encoder names (video / audio) | Video, audio | Source units in the output: video identical / windows; audio identical / windows | Canaries (SEI, DSE) |
|---|---|---|---|---|
| DESIGN | `c2.android.avc.encoder` / `c2.android.aac.encoder` | transcoded, transcoded | 0 / 0 of 1 080; 0 / 1 486 of 1 686 | 0, 0 |
| UNFORCED_EFFECTS | same | transcoded | 0 / 0; 0 / 1 486 | 0, 0 |
| PLAIN | same | transcoded | 0 / 0; 0 / 1 486 | 0, 0 |
| PLAIN_KEEP_HDR | same | transcoded | not compared | 0, 0 |
| PLAIN_DEFAULTS | **null / null** | **transmuxed** | **360 of 360 / 1 016; 562 of 562 / 1 686** | SEI dropped by the filter (360), **DSE 562** |

- **Forcing works, and is already Media3's behaviour once settings are requested.** In 1.11.1, `DefaultEncoderFactory.videoNeedsEncoding()`/`audioNeedsEncoding()` return true whenever requested encoder settings differ from the defaults, and `TransformerUtil.shouldTranscodeVideo` returns true for any HDR mode other than `KEEP_HDR`; only the control with neither transmuxed. The design's wrapper and its `ExportResult` check (§6.2) are the guard against a future version changing that.
- **No source unit survives a forced export:** 0 identical NAL units and 0 identical AAC frames, and no canary. The 1 486 audio windows are not survivals: the source's audio is a steady synthetic tone encoded by the same `c2.android.aac.encoder`, so re-encoding the decoded tone reproduces long identical byte runs inside frames that differ as wholes (the DSE canary at the start of every source frame is gone). Real audio will not repeat this; the check that matters is whole frames and canaries.
- **The SPS is the encoder's; the VUI colour description is the source's.** Every output's SPS is `c2.android.avc.encoder`'s (Baseline, level 4.1, `pic_order_cnt_type` 2), but its VUI colour description and full-range flag are copied from the source: the BT.601 full-range source gives `colour_primaries` 5, `transfer` 1, `matrix` 6, `full_range` 1 in every configuration (and the `colr` box of the sample entry the same, V-M3), while the source without a colour description gives (1, 1, 1) limited. Transformer passes the decoded `ColorInfo` to the encoder's format. With the fix under test the BT.601 source gives (1, 1, 1) limited too.
- **The fix converts, it does not only relabel** (2026-10-04, `results/api29gles/luma-vm17.txt`: the first frame of each file decoded by `MediaCodec` into a buffer, so the coded luma values are read without any conversion; the preview path through an `ImageReader` surface cannot do this, it returns 16..235 for every input). The source codes luma 0..255 (full range, as labelled). API 35's DESIGN output keeps 0..255 under its full-range label; with the fix the output codes **10..242** under the BT.709 limited label (limited range plus coding overshoot at the gradient's edges), byte-size-identical to the export of the source without a colour description.
- HDR: no HDR source or 10-bit HEVC encoder exists on the emulators, so tone-mapping was configured but never exercised (§25).

**Results, API 29** (the GLES 3 boot of §1, 2026-10-04, `results/api29gles/transcode-vm1-observe.txt`, `transcode-save.txt`, `nalcmp-canary.txt`, `luma-vm17.txt`, `exif-oracle-video.txt`).
- The same five configurations: DESIGN, UNFORCED_EFFECTS, PLAIN and PLAIN_KEEP_HDR transcoded with **`OMX.google.h264.encoder` / `OMX.google.aac.encoder`** (both names set); PLAIN_DEFAULTS transmuxed (both null) and is again the only output with a canary (the DSE, 562).
- Forced outputs: 0 identical NAL units (1 of 1 080 windows), 0 identical AAC frames (1 486 of 1 686 windows: the same FDK-based AAC encoder family re-encoding the same tone, as on API 35), 0 canaries; ExifTool finds 0 tags outside the structural allowlist in all 18 outputs.
- **The colour signalling is wrong without the fix.** `OMX.google.h264.encoder` writes a VUI without a colour description, and the pixels it codes are limited range (luma **13..240**) whichever source is given, but the `colr` box (written from Transformer's track format) still says BT.601 **full** range (5, 1, 6, full) for the BT.601 source: a player that trusts the container shows those limited-range pixels with too little contrast. With the fix, the `colr` box says BT.709 limited and matches the pixels; the output is then byte-identical to the export of the source without a colour description.

**Verdict: CORRECTS** the design on one point: forced encoding happens (both names set, no source unit or canary survives, on API 29 and 35), but the output's colour signalling is not the device encoder's: the VUI colour description and range flag (API 35) and the `colr` box (both levels) carry the source's values, and on API 29 the `colr` label even contradicts the coded pixels. Setting the encoder format's colour to SDR BT.709 limited fixes both on both levels.

**Normative correction (S0-13).**
1. §8.3, Transformer configuration: "the forcing encoder factory sets `Format.colorInfo = ColorInfo.SDR_BT709_LIMITED` on the format it passes to `DefaultEncoderFactory.createForVideoEncoding` (every SDR output is BT.709, limited range; the frame processor converts the pixels: S0 V-M17 measured luma 0..255 → 10..242 on API 35, and on API 29 a `colr` label that matches the limited pixels instead of the source's full-range label)."
2. §8.3, canonical fMP4 profile: "`colr` is `nclx` (1, 1, 1, full_range_flag 0); the SPS VUI either has no colour description or exactly (1, 1, 1) with `video_full_range_flag` 0; anything else is `NON_CANONICAL`." (This replaces "the output SPS/VUI are the device encoder's" in V-M17's statement and S0-3's `colr` line.)
3. §15.7 corpus, matching-source row: the source is BT.601 full range with planted SEI and DSE canaries (as in S0), and the test decodes the output into buffers and asserts luma within 16 ± 8 … 235 ± 8, so that a relabel without conversion fails.
4. HDR tone-mapping remains unexercised (no HDR source or 10-bit encoder on the emulators): it is a device row of S0b (§25).

---

## 18. V-M18: a fresh isolated process per request, and its cost

**Question (C.3).** Does a fresh isolated process per request (`bindIsolatedService` with a new instance name) bind, decode and die on API 29, 35 and 37, and is its cold-start cost acceptable for a screen of previews (Q25's fallback otherwise)?

**Method.** The `isoTiming` probe makes 100 sequential requests, each in its own instance (`IsoClient.oneShot`: `bindIsolatedService(intent, BIND_AUTO_CREATE, "t_" + 16 random hex digits, executor, connection)`), decoding the 320-px canonical preview `preview320.jpg` (1 446 B) to ARGB pixels through `SharedMemory`, then unbinding and waiting for `binderDied`. It records the PIDs, the time to `onServiceConnected`, bind + decode + reply, and unbind → death. Two sessions per API level: 2026-09-25 and 2026-10-03 (the second with other builds holding the host at 97–100 % CPU).

**Results** (`results/api{29,35}/isoTiming.txt`, first session under `2026-09-25/`).

| | API 29, 09-25 | API 29, 10-03 | API 35, 09-25 | API 35, 10-03 |
|---|---|---|---|---|
| failures / distinct PIDs | 0 / **100** | 0 / **100** | 0 / **100** | 0 / **100** |
| bind (median / p90 / max) | 191 / 202 / 227 ms | 466 / 945 / 3 341 ms | 426 / 575 / 900 ms | 742 / 993 / 1 866 ms |
| **bind + decode 320 px + reply** (median / p90 / max) | **199 / 211 / 238 ms** | **511 / 1 018 / 3 520 ms** | **479 / 676 / 1 013 ms** | **836 / 1 171 / 2 152 ms** |
| unbind → process death (median), deaths seen | 5.4 ms, 100/100 | 16.0 ms, 100/100 | 11.0 ms, 100/100 | 16.0 ms, 100/100 |

Every request got its own process (100 distinct PIDs of 100) and every process was gone within milliseconds of the unbind; a STRIP and a DECODE never shared one (V-M5 records their PIDs). The cost is the process start (`bind` is 89–96 % of the total); the decode of a preview is a few milliseconds. On the emulator the start costs 0.2–0.8 s at the median, rising with the host's load (the same image doubled between the two sessions), with outliers to 3.5 s; the emulator runs the guest's processes on emulated CPUs of a loaded host, so none of these numbers transfers to a phone.

**Verdict:** the mechanism **CONFIRMS** the design on API 29 and 35 (fresh process per request, distinct PIDs, death after unbind; API 37 not available here, §25); whether the cost is **acceptable is INCONCLUSIVE**: the design gives no criterion, and the only meaningful numbers come from the reference phones (S0b). At the emulator's medians a screen of eight previews with `MAX_DECODER_PROCESSES = 2` needs 0.8–3.3 s.

**Normative correction (S0-14).**
1. §9.2, "One process instance per request" bullet, last sentence: replace "The cost is one isolated-process start per request, measured in S0a (V-M18); if it is too slow for previews, Q25's fallback …" by "The cost is one isolated-process start per request: 0.2–0.8 s at the median on the S0 emulators (V-M18; host-load dependent, not a device figure). **Criterion:** on the reference mid-range phone (S0b), the p90 of bind + 320-px decode + reply must be ≤ 250 ms, so that two instances fill a screen of eight previews in about one second; above it, Q25's fallback applies to previews (one instance per sender and screen), never to `STRIP_IMAGE` or a full decode. Previews show a placeholder until decoded."
2. Q25 gains the criterion and the measured emulator range (owner question S0 Q-S2: accept 250 ms p90 as the threshold).

---

## 19. V-M19: the Application in the isolated process

**Question (C.3).** With the `Process.isIsolated()` early return, does the Application do nothing in `:mdec`, and does no content provider or initializer run there? Without it, how does a bind fail (mutant MC-M23)?

**Method.** The probe's `SpikeApp` reproduces `GhostApp.onCreate`'s kind of work (`GhostApp.kt:146-158`): a no-backup file write, an `AndroidKeyStore` load and a `ConnectivityManager` call. In an isolated process it records in a static field that it ran and returns right after `super.onCreate()`, unless the process name contains `unguarded` (the mutant: then it does the same work, uncaught). The isolated `IsoService` answers a `PING` with its PID, UID, `Process.isIsolated()`, its process name, whether `SpikeApp.onCreate` ran there and whether the probe's `SourceProvider` (a non-exported provider of the default process) was created there, and an `OPS` request that tries each GhostApp-like operation separately and reports how it fails. `iso` and `unguarded` probes, on API 29 and API 35 (2026-09-25; the API 35 `iso` probe was re-run on 2026-10-03 with identical results apart from PIDs and timings).

**Results.**

| | API 29 | API 35 |
|---|---|---|
| isolated instance | UID 99016, `isIsolated = true`, process `org.ghost.spike.media:mdec:org.ghost.spike.media.IsoService:ping_306a…` | UID 99185, `isIsolated = true`, `…:mdec:…IsoService:ping_a204…` |
| `Application.onCreate` ran there | **yes** | **yes** |
| a provider created there | no (`SourceProvider` only in the main process) | no |
| no-backup file write | `FileNotFoundException` (EACCES) | `FileNotFoundException` (ENOENT) |
| list the data directory | `NullPointerException` (no listing) | same |
| `AndroidKeyStore.load(null)` | succeeds | succeeds |
| `ConnectivityManager.getActiveNetwork()` | `NullPointerException` (no manager) | same |
| `ContentResolver.query` | `SecurityException` "Isolated process not allowed to call getContentProvider" | same |
| a TCP socket | `SocketException` (EACCES) | same |
| guarded bind (early return) | connected in 209 ms | connected in 476 ms |
| unguarded bind (MC-M23) | **no callback within 15 s** (`timeout(none)`) | **no callback within 15 s** |

The isolated process gets the Application like any other (the platform documents nothing else, and here it is observed); a provider of the default process is not instantiated there. Every GhostApp-like operation except a bare Keystore load fails inside it, and the first uncaught one kills the process before the service is bound, so the client sees neither `onServiceConnected` nor `onBindingDied`: the request would hang until the 10-s timeout of §9.2. The early return removes that.

**Verdict: CONFIRMS** §9.2 and V-M19 as designed (early return required; no provider runs there; MC-M23 is detectable by the binding test: the mutant's bind never connects).

**Normative correction (S0-15, precision only).** §9.2, "The Application does nothing in the isolated process" bullet, append: "Without the early return, a bind never connects (no `onServiceConnected`, no `onBindingDied`; observed on API 29 and 35), so MC-M23 shows as a request timeout, not as a crash the client can see; the binding test asserts a connection within 2 s (S0: 0.2–0.5 s on the emulators)."

---

## 20. V-M20: task snapshots, tombstones, dropbox and bug reports

**Question (C.3).** On API 29–32, does a FLAG_SECURE window's task snapshot hold no media pixels; on 33+, does `setRecentsScreenshotEnabled(false)` prevent it; and what does a forced `:mdec` crash leave in `/data/tombstones` and dropbox (recorded, not required to be empty, L9-M8)? C.2 also notes that the claim "tombstones and dropbox entries are included in an `adb bugreport`" was not re-fetched and that V-M20 observes it.

**Method.**
1. *Snapshots* (`scripts/vm20-snapshots.sh`, `adb root` on the userdebug images): `ViewerActivity` shows a full-screen pattern of saturated magenta and lime stripes with a cyan square (colours no system UI uses) in four variants: plain, FLAG_SECURE, `setRecentsScreenshotEnabled(false)` (API 33+ only), both. For each: force-stop, empty `/data/system_ce/0/snapshots`, start the activity, `screencap`, HOME (the system persists the task snapshot), the Recents screen (`screencap`), then pull every file of the snapshot directory. `scripts/count-pattern.ps1` counts, on a 4-pixel grid, the pixels matching each pattern colour in every snapshot and screenshot.
2. *Crashes* (`scripts/vm20-crash.sh`): a fresh `:mdec` instance fills a 512 KiB direct buffer with `GHOST-S0-PLAINTEXT-CANARY-` and crashes: mode 1 natively, in `libghost_spike_crash.so` (`rust/crashlib`, x86_64), with several registers pointing into the buffer, the way a decoder crashing on a malformed image crashes with registers in its pixel buffer; mode 2 an uncaught Java exception; mode 3 `kill -SEGV` of itself. Then every file newer than a marker under `/data/tombstones` and `/data/system/dropbox` is pulled and searched for the canary (raw and inside gzip members), and an `adb bugreport` (no root needed) is taken and every entry of its zip searched the same way.

**Results, API 35.**
- *Snapshots* (2026-09-25, `results/api35/vm20/`): the system wrote a snapshot in **every** variant (`N.jpg` 1 080 × 1 920, `N_reduced.jpg` 540 × 960, `N.proto`). Plain: 66 242 B, **47 701 magenta, 46 623 lime and 9 804 cyan** sampled pixels of 129 600 (the media). FLAG_SECURE: 15 592 B, **0 / 0 / 0**. `setRecentsScreenshotEnabled(false)` alone: 15 592 B, **0 / 0 / 0**. Both: 15 592 B, 0 / 0 / 0. The three protected snapshots are byte-for-byte the same size: a placeholder without the window's content. `screencap` of a FLAG_SECURE window is black (129 114 of 129 600 pixels); the Recents screen shows no pattern pixel for any protected variant.
- *Tombstones and dropbox* (2026-09-25 for modes 1–3; mode 1 again on 2026-10-03 with the bug report, `results/api35/crash-artefacts-mode1.txt`, `2026-09-25/crash-artefacts.txt`). The native crash (mode 1) left `tombstone_NN` (≈ 410–419 KB text) and `tombstone_NN.pb` (≈ 252–259 KB), plus dropbox `data_app_native_crash@…`, `SYSTEM_TOMBSTONE@….txt.gz` and `SYSTEM_TOMBSTONE_PROTO_WITH_HEADERS@….dat.gz`. **The canary is in them**: 79 (2026-09-25) and 81 (2026-10-03) raw copies in the `.pb`, as many inside the dropbox proto, and in the text tombstone's "memory near" dumps of `rax`, `rbx`, `rdx` …, where 13 lines show `GHOST-S0-PLAINTE…` in the ASCII column (the canary is split across 16-byte lines, so a plain search of the text form finds 0). The Java crash (mode 2) left only `data_app_crash@…` (753 B, a Java stack, 0 hits); mode 3 a tombstone without the buffer in any register's neighbourhood (0 hits).
- *Bug report* (2026-10-03, 3 927 633 B, 156 entries, `adb bugreport` without root): it carries `FS/data/tombstones/tombstone_00`, `tombstone_00.pb`, `tombstone_01`, `tombstone_01.pb` and the dropbox entries of the day, and **the canary is found in `tombstone_00.pb` (79), `tombstone_01.pb` (81) and the dropbox proto (81)**. `tombstone_00` is the crash of **2026-09-25 08:52:13**: eight days later it was still on the device and still went into the bug report, while the 2026-09-25 dropbox copies had expired. Tombstones are rotated by count, not by age.

**Results, API 29** (2026-10-03, `results/api29/vm20/`, `crash-artefacts-mode1.txt`).
- *Snapshots:* again a snapshot in every variant. Plain: 58 103 B, **49 219 magenta, 49 319 lime, 8 118 cyan** sampled pixels. FLAG_SECURE: 16 032 B, **0 / 0 / 0** (the only dark pixels are the system bars, present in every variant). `setRecentsScreenshotEnabled` does not exist below API 33, so the "noRecents" variant equals the plain one (pattern present) and "both" equals FLAG_SECURE. `screencap` of a FLAG_SECURE window fails outright on API 29 (black on API 35).
- *Tombstones and dropbox:* API 29 writes text tombstones only (no `.pb`): `tombstone_01` (491 293 B) has **14 lines** whose hex dump shows `GHOST-S0-PLAINTE…` in the ASCII column; the dropbox copy `SYSTEM_TOMBSTONE@….txt.gz` has the same 14 lines; `data_app_native_crash@….txt.gz` holds the header and stack.
- *Bug report* (1 965 827 B, 151 entries, no root): it carries `FS/data/tombstones/tombstone_00` and `tombstone_01`, the latter with the 14 canary lines; the dropbox files are not in this version's zip.

**Verdict: CONFIRMS** the design's controls and declarations, with one correction to the test method and API 30–32 unmeasured. FLAG_SECURE keeps the window's pixels out of the persisted task snapshot on API 29 and API 35 (a placeholder snapshot is still written), and `setRecentsScreenshotEnabled(false)` does so alone on API 35; API 30–32 have no image on this workstation (§25). The OS-written crash residue is exactly the declared L9-M8 one, now measured: the memory around a crashing decoder's registers (the canary in every form) reaches the tombstone, the dropbox copy and, without root, the bug report; tombstones are rotated by count, not by age (an eight-day-old one was still there). A plain byte search of the text forms finds nothing, because the hex dump splits the bytes across lines: a scan that only greps would report 0 hits on a tombstone full of plaintext.

**Normative correction (S0-16).**
1. §10.3, task-snapshot row, "Control" column: append "measured in S0 (V-M20): with FLAG_SECURE, API 29 and API 35 persist only a placeholder snapshot (no pattern pixel of 129 600 sampled); on API 35 `setRecentsScreenshotEnabled(false)` alone does the same; API 30–32 are measured by the emulator job (or the checklist) before the gate. Both controls stay (defence in depth)."
2. §10.3, tombstone row, and L9-M8 (Appendix B.4): "measured in S0 (V-M20): a native crash of a `:mdec` instance writes the memory around its registers (a few hundred bytes per register) into `/data/tombstones/tombstone_NN` (text, and on API 35 also `.pb`), into dropbox (`SYSTEM_TOMBSTONE`, compressed), and `adb bugreport` carries `/data/tombstones` without root on API 29 and 35; tombstone files are rotated by count (a fixed number of slots `tombstone_00`, `tombstone_01`, …), not by age, so such plaintext can outlive every media object by weeks, while dropbox copies expire after days. A Java crash leaves only a stack."
3. §15.8 item 1, system-directory scan: "the search over tombstones decodes the text form's hex dumps (the `memory near …` blocks) back to bytes before searching, and also searches `.pb` files and gunzipped dropbox entries; a plain byte search of the text form misses every hit (S0 V-M20: 13–14 hex-dump lines with the canary, 0 raw matches)". The scan's report line names the API levels measured.

---

## 21. V-M21: what the photo picker and DocumentsUI keep about a pick

**Question (C.3).** What do the photo picker (API 30+) and DocumentsUI (API 29's `ACTION_OPEN_DOCUMENT`, `PickVisualMedia`'s fallback there) persist about a pick: recents, last-accessed entries per package? Declared per API level (L9-M15); nothing GHOST can change.

**Method.** `scripts/vm21-picker.sh <api> <image>`: pushes the test image to `/sdcard/Pictures/` under a fresh name and has MediaProvider index it; stops DocumentsUI (a stale instance left in the probe's task by an earlier run would otherwise receive the pick, see below); as root, hashes every file of the picker-side packages (`com.android.providers.media.module`, the legacy `com.android.providers.media`, `com.android.documentsui`, the photo-picker package where it exists) and of the system records a pick could touch (`/data/system/urigrants.xml`, `/data/system_ce/0/recent_tasks`, `recent_images`, the usage-stats directories); starts the `pick` probe, whose `PickActivity` launches `MediaStore.ACTION_PICK_IMAGES` on API 33+ and `ACTION_OPEN_DOCUMENT` (`image/*`) otherwise and reads the returned stream under a `FileObserver` over every app directory (V-M11); taps the picture found by `uiautomator`; hashes again, pulls every changed file, dumps the rows of changed databases that name the package or the file, and lists every file of shared storage (`/data/media/0`) written during the pick. Since 2026-10-04 the probe also writes the bytes it received to `files/picked.bin` after its observation ends, and the script compares them with the pushed file.

**Results, API 35 (photo picker, `ACTION_PICK_IMAGES`; 2026-10-03 `results/api35/vm21-2026-10-03/`, 2026-10-04 `results/api35/vm21/` with the shared-storage listing and the picked bytes).** Both picks returned `content://media/picker/0/com.android.providers.media.photopicker/media/<id>` with flags `0x41` (read grant plus a *persistable* grant). Changed between the two snapshots, or written to shared storage during the pick:
- **Two thumbnails of the picture.** `com.android.providers.media.module/cache/image_manager_disk_cache/<hash>.0`, a 600 × 400 baseline JPEG (4 283 B) at the displayed orientation, the photo picker's Glide disk cache (its `journal` changed with it); and **`/sdcard/Pictures/.thumbnails/<id>.jpg`** (4 283 B), MediaProvider's thumbnail in shared storage (owner MediaProvider, `media_rw`, mode 0660, behind the FUSE layer), written when the picker displayed the picture, 20 s before the pick. Both are decoded and re-encoded copies of the picture, outside GHOST; the thumbnail of the picture picked on 2026-09-25 (`1000000018.jpg`) was still there on 2026-10-04.
- **`/sdcard/.transforms/synthetic/picker/0/com.android.providers.media.photopicker/media/<id>.jpg`**, written at the moment of the pick: a file of the picked file's length (4 341 B) **filled with zeros**, MediaProvider's placeholder for the URI it served; the placeholder of the 2026-09-25 pick (`1000000018.jpg`, 09:10:09) was still there nine days later. Its name and time record which picture was picked and when.
- `databases/picker.db` (its WAL, 2026-10-03): the picker's mirror of MediaStore (`media`: one row with `local_id`, date taken, size, dimensions, orientation, MIME, `sync_generation` 21) and `shared_prefs/picker_sync_prefs.xml` (`last_media_sync_generation` 21): the picker synchronises when it opens.
- `databases/external.db` WAL: MediaStore bookkeeping; `media_grants` (Android 14+'s per-package grant table) has **0 rows**: no grant to the probe package is recorded. `app_logs/<time>`: MediaProvider's own scan log (no pick in it).
- `/data/system_ce/0/recent_tasks/<n>_task.xml`: the probe's own task record (its activities, `calling_package` = the probe), as for any app task.
- Not changed: `/data/system/urigrants.xml` does not exist (the persistable grant was offered and never taken; GHOST never takes one), DocumentsUI's files, the usage-stats files (flushed on the service's schedule; their absence from a few-minute window proves nothing).
- **The stream is not the file: the location is zeroed.** All three picks (2026-09-25, 10-03, 10-04) returned 4 341 bytes, the file's length, with another SHA-256 (`fe4398d4…` against `6922c84d…`). The 2026-10-04 run kept the bytes (`picked.bin`, `picked-vs-pushed.txt`): 23 bytes differ, all inside the EXIF GPS directory, all set to 0 (ExifTool reads `GPSLatitudeRef`/`GPSLongitudeRef` "Unknown" and empty coordinates), while Make, Model, the serial number, `DateTimeOriginal` and the orientation pass unchanged: the photo picker hands over the picture with its location zeroed (the probe holds no `ACCESS_MEDIA_LOCATION`, like GHOST). DocumentsUI on API 29 hands over the file unchanged, GPS included. STRIP removes all of it on both levels (V-M4, V-M6).

**Results, API 29 (DocumentsUI, `ACTION_OPEN_DOCUMENT`; 2026-10-04, `results/api29/vm21-first/` and `results/api29/vm21/`, two picks of two pictures).** Both picks returned `content://com.android.providers.media.documents/document/image%3A14` (and `…%3A15`) with flags `0x43` (read, **write**, persistable), and the stream was the pushed file, byte for byte (its SHA-256). DocumentsUI and MediaProvider keep:
- **`com.android.documentsui/databases/lastAccess.db`, table `lastAccessed`, one row per calling package:** `package_name` = the probe, `timestamp` = the time of its last pick (ms), `external` 0, and `stack`, a 520-byte serialised `DocumentStack` naming the root (`com.android.providers.media.documents`, `images_root`, "Images") and **the folder of the picked file** (`images_bucket:-1617409521`, "Pictures"). It is used to reopen the picker for that package where it last picked: once a pick was recorded, the next runs opened directly in "Images on phone" › "Pictures" (`ui-1.xml` of both runs), where the first runs had opened on the empty "Recent" root.
- **`com.android.documentsui/databases/pickCountRecord.db`, table `pickCountRecordTable`: one row per picked file, for every app:** `file_hash_id` = Java `String.hashCode()` of the picked document's URI (1436924597 = the hash of `content://com.android.providers.media.documents/document/image%3A14`, 1436924598 of `…%3A15`, recomputed on the host) and `pick_count` (2 after the second pick of the same file). A 32-bit unkeyed hash: anyone holding the device can recompute it for every picture and learn which were picked and how often.
- **MediaProvider writes a thumbnail of every picture DocumentsUI shows into shared storage:** `/sdcard/Pictures/.thumbnails/14.jpg` (3 812 B, written at 00:04:25.71, when the grid first showed the picture) and `15.jpg` (3 799 B, 1.6 s after the picker opened in the last run): 600 × 400 baseline JPEGs of the pictures at their displayed orientation, in shared storage (`media_rw:media_image`, mode 0664, under API 29's sdcardfs), where an app with the storage permission and legacy storage access (one targeting API 28 or lower, or one that opts out of scoped storage) reads them by path. They are written for every picture the picker displays, picked or not, and stay.
- System records: the probe's task record (`recent_tasks/N_task.xml`), and the usage stats (`/data/system/usagestats/0/{daily,weekly,monthly,yearly}/…`), which name `com.android.documentsui.picker.PickActivity` and the probe's activities with times (seen in the 19-minute run, flushed on the service's schedule, absent from the 3-minute runs). `urigrants.xml` is absent (no persisted grant); `search_history.db` stays empty (no search).
- A trap of the method, worth knowing for the product's tests: a DocumentsUI instance left from an earlier run stayed in the probe's task after the probe was force-stopped; the next run's `NEW_TASK` start of `PickActivity` only brought that stale task to the front (no `START` of DocumentsUI in the log), the pick went to the dead requester, and DocumentsUI still recorded it (`pickCountRecord`, `lastAccess`).

**Verdict: CORRECTS** L9-M15's content (the approach stands: the OS writes these, GHOST cannot prevent them, they are declared). The design names "recent documents, last-accessed entries per package"; what the OS keeps is more: **decoded thumbnails of the pictures** outside GHOST on both API levels (API 35: in MediaProvider's private Glide cache and in shared storage's `Pictures/.thumbnails`; API 29: of every picture shown, in shared storage), a placeholder file named after the picked item with the time of the pick (API 35), a per-file pick counter keyed by an unkeyed hash of the URI (API 29), and the folder and time of GHOST's last pick under GHOST's package name (API 29); these outlive the pick by days at least (nine, measured). API 30–34 and 36–37 are not measured (§25).

**Normative correction (S0-17).**
1. L9-M15 (and Appendix B's copy, §6.1's "What the picker … record about a pick" sentence): replace the description by the measured list: "API 35 photo picker: a 600-px JPEG thumbnail of the picture in MediaProvider's private Glide cache (`image_manager_disk_cache`) and another in shared storage (`Pictures/.thumbnails/<id>.jpg`, MediaProvider's, 0660), a zero-filled placeholder named after the picked item and written at the pick (`.transforms/synthetic/picker/…/<id>.jpg`), the picker's MediaStore mirror (`picker.db`), GHOST's task record; no grant record (`media_grants` empty, no `urigrants.xml`); thumbnails and placeholders outlive the pick (nine days measured). API 29 DocumentsUI: GHOST's package name with the folder and time of its last pick (`lastAccess.db`), a per-file pick counter keyed by `String.hashCode()` of the document URI (`pickCountRecord.db`), and a 600-px JPEG thumbnail of **every picture the picker displays** in shared storage (`Pictures/.thumbnails/<id>.jpg`, mode 0664, readable by path by apps with the storage permission and legacy storage access); usage-stats entries for the picker activity on both. The photo picker hands GHOST the picture with its location zeroed; DocumentsUI hands over the file unchanged. Measured in S0 (V-M21); other API levels by the emulator job or the checklist."
2. Threat model and the user-facing privacy text: the thumbnails are image content outside GHOST, linkable to GHOST on API 29 through `lastAccess.db` (package name, folder, time); on API 35 the placeholder's name and time say which picture was picked when; a reader of a seized phone, or on API 29 another app with storage access, can see which pictures were browsed or picked, not that or to whom they were sent.
3. Owner question S0 Q-S4: accept and declare (default), or show a one-time notice before the first pick ("the system picker keeps a small copy of the photos it shows"), or refuse picking on API 29, where the residue also names GHOST.
4. §15.8's system-directory scan gains `/data/media/0/**/.thumbnails`, `/data/media/0/.transforms/synthetic`, MediaProvider's `cache/image_manager_disk_cache` and DocumentsUI's databases, so that the emulator job records these per API level.

---

## 22. V-M22: bitrate overshoot at 2 Mbit/s over whole files

**Question (C.3).** Does the encoders' overshoot at 2 Mbit/s (CBR where supported, else VBR) stay below 20 % over whole files (20 transcodes of the corpus's longest sources; output size against duration)? §6.1's limits rest on it: `VIDEO_MAX_MS` = 160 s and `VIDEO_MAX_MS_SHORT` = 85 s are the byte budgets (52 428 800 B, class 8's 28 309 824 B) divided by 1.2 × 2.128 Mbit/s.

**Method.** `SourceMaker` makes the sources on each emulator with that emulator's own H.264 encoder at 4 Mbit/s: three 160-s 1 280 × 720 30-fps sources of increasing difficulty, `smooth` (a moving gradient and a moving box), `grain` (the gradient with ±8 luma noise on every pixel, a stand-in for sensor noise) and `mixed` (the gradient plus a white-noise patch over 1/16 of the frame), and 10-s versions of the three plus `noise` (full-frame white noise, a worst case). `Transcoder.Mode.DESIGN` transcodes each (`set short`: every 10-s source in CBR and VBR; `set long`: every 160-s source in CBR twice; `set longvbr`: once in VBR), counting the bytes `GhostMuxer` writes instead of keeping them (a sealer's view). `scripts/vm22-summary.sh` computes the whole-file rate (container and audio included) against the profile's 2.128 Mbit/s and what 160 s and 85 s would weigh at that rate. API 35's encoder is `c2.android.avc.encoder` (software, CBR supported); API 29's is `OMX.google.h264.encoder` (software, **no CBR**, so every API 29 export ran VBR), on the GLES 3 boot of §1. The phones are S0b.

**Results, API 35** (2026-10-03; `results/api35/transcode-{short,long,longvbr}.txt`, `transcode-longvbr-grain-rerun.txt`, `sources-{short,long}.txt`).

| Source | Mode | Whole-file rate | Overshoot | 160 s would weigh | 85 s would weigh |
|---|---|---|---|---|---|
| 160 s `smooth` | CBR (×2, identical) | 2.136 Mbit/s | **+0.4 %** | 42.7 MB (fits 50 MiB) | 22.7 MB (fits class 8) |
| 160 s `grain` | CBR (×2, identical) | 2.137 Mbit/s | **+0.4 %** | 42.7 MB | 22.7 MB |
| 160 s `mixed` | CBR (×2, identical) | 5.623 Mbit/s | **+164.2 %** | 112.5 MB (**over**) | 59.7 MB (**over**) |
| 160 s `smooth` | VBR | 2.198 Mbit/s | +3.3 % | 44.0 MB | 23.4 MB |
| 160 s `mixed` | VBR | 2.739 Mbit/s | **+28.7 %** | 54.8 MB (**over**) | 29.1 MB (**over**) |
| 160 s `grain` | VBR (re-run, see below) | 2.205 Mbit/s | +3.6 % | 44.1 MB | 23.4 MB |
| 10 s `smooth` | CBR / VBR | 2.151 / 2.079 | +1.1 % / −2.3 % | | |
| 10 s `grain` | CBR / VBR | 2.152 / 2.149 | +1.1 % / +1.0 % | | |
| 10 s `mixed` | CBR / VBR | 5.731 / 2.903 | **+169.3 % / +36.4 %** | | |
| 10 s `noise` | CBR / VBR | 92.19 / 54.09 | **+4 232 % / +2 442 %** | | |
| the 6–12-s corpus sources of V-M24 (mixed content) | CBR | 2.45 … 4.63 | +15 % … +118 % | | |

**Results, API 29** (2026-10-04; `results/api29gles/transcode-{short,longvbr,save}.txt`, `sources-{short,long}.txt`; the sources were made on API 29 by `OMX.google.h264.encoder`, which refuses the profile and colour keys, so they were made without them, and which failed outright on the full-frame `noise` source, `IllegalStateException`).

| Source | Mode | Whole-file rate | Overshoot | 160 s would weigh | 85 s would weigh |
|---|---|---|---|---|---|
| 160 s `smooth` | VBR | 2.140 Mbit/s | **+0.6 %** | 42.8 MB (fits 50 MiB) | 22.7 MB (fits class 8) |
| 160 s `grain` | VBR | 2.140 Mbit/s | **+0.6 %** | 42.8 MB | 22.7 MB |
| 160 s `mixed` | VBR | 5.274 Mbit/s | **+147.8 %** | 105.5 MB (**over**) | 56.0 MB (**over**) |
| 10 s `smooth` | VBR (×2, identical) | 2.161 Mbit/s | +1.5 % | | |
| 10 s `grain` | VBR (×2, identical) | 2.172 Mbit/s | +2.1 % | | |
| 10 s `mixed` | VBR (×2, identical) | 5.337 Mbit/s | **+150.8 %** | | |
| 10 s `noise` | — | — | (source could not be made) | | |
| the 6–12-s corpus sources (landscape coding) | VBR | 2.16 … 3.76 | +1.7 % (VGA) … +76.7 % | | |

- Both encoders are deterministic: repeated exports gave byte-identical lengths, so repetitions add nothing on the emulators; the variance the design's "20 transcodes" aims at exists only on hardware encoders (S0b).
- Both hold the target on content they can compress (`smooth`, `grain`: ≤ +3.6 % over 160 s on API 35, +0.6 % on API 29) and miss it widely once a noise patch covers 1/16 of the picture: API 35 by a factor of 2.6 in CBR and 1.3 in VBR, API 29 by a factor of 2.5 in VBR (+147.8 % over 160 s, +150.8 % on the 10-s source); API 35 misses by 25–43× on full-frame noise. **CBR overshoots more than VBR** on API 35's encoder whenever the content is hard.
- One API 35 VBR export (`long160_grain`) **stalled without an error**: no progress after 82 s of media (2 467 video samples, 22 300 542 B), no callback, until the probe's 900-s timeout; the system log showed nothing until the process was killed. The re-run of the same export completed normally (249 s, +3.6 %): the stall is intermittent, an emulator decoder-to-encoder pipeline that stopped once in ten 160-s exports on API 35. None of the 64 API 29 exports stalled (two `noise` exports failed at once: their source could not be made).
- Cost on the emulators: a 160-s source took 152–249 s to transcode on API 35 (0.95–1.6 × real time) and 144–332 s on API 29 (0.9–2.1 × real time), on the loaded host; the app's `VmHWM` reached 219–238 MB (API 35) and 209–247 MB (API 29) while counting (no output kept).

**Verdict: CORRECTS** the design. The 20 % margin is not a property of an encoder but of content and encoder together, and on both emulator encoders it fails on hard content: API 35 by +29 % (VBR) to +169 % (CBR) with a noise patch and by up to +4 232 % on full-frame noise, API 29 by +148 % to +151 % with the noise patch in its only mode (VBR); the design's preferred mode (CBR) is the worse one where both exist. The privacy property is safe (the sealer's class check fails closed, `OVERSIZE`); what fails is the user's send, after part or all of a long transcode.

**Normative correction (S0-18).**
1. §6.1, last two sentences of the "Limits before work" bullet: replace the overshoot-margin rationale by: "Encoders do not hold the requested bitrate on hard content (S0 V-M22, emulator encoders of API 29 and 35: ≤ +3.6 % on smooth and grainy 160-s sources; with a noise patch over 1/16 of the frame +29 % (VBR) to +169 % (CBR) on API 35 and +148 % to +151 % on API 29 (VBR); +2 442 % to +4 232 % on full-frame noise). `VIDEO_MAX_MS` (160 s) and `VIDEO_MAX_MS_SHORT` (85 s) therefore limit the source's duration only; the class cap is enforced while the stream is sealed: `sealAppend` returns `OVERSIZE` as soon as the content passes `maxClass`'s capacity, `GhostTranscoder` cancels the export at once, and the preparation is retried **once** as a new object at `bitrate × 0.9 × capacity / projected size` (projected from the bytes sealed and the media time reached), then fails with `TOO_LARGE`. Both attempts count against `MAX_CONCURRENT_PREPARATIONS`." (Owner question Q-S3: keep the limits with this retry, or also lower them.)
2. §6.1 and §8.3: "the video bitrate mode is VBR; CBR only on an encoder whose measured overshoot (S0b, the reference phones) is lower in CBR than in VBR" (on API 35's emulator encoder CBR is worse; API 29's has no CBR at all).
3. §6.2: "`GhostTranscoder` watches progress (`Transformer.getProgress`) and cancels an export that has not advanced for 30 s (`UNSUPPORTED_SOURCE`, counted; the orphans are reconciled), since an export can stall without an error (S0 V-M22, once in ten exports of 160-s sources on the API 35 emulator)."
4. R-M17: likelihood "high" (measured), impact "medium" (a failed or retried send), mitigation as point 1.
5. V-M22 (S0b) keeps the device measurement, now of: the overshoot of each reference phone's encoder in both modes on the `smooth`, `grain` and `mixed` sources (made on the phone itself), and the retry's success rate.

---

## 23. V-M23: the video preview path (first frame into an `ImageReader`)

**Question (C.3).** Does a Media3 player over `ContentDataSource` render a source's first frame into an `ImageReader` surface on API 29, 35 and 37, writing no file (§6.2's preview path; the fallback is no preview for video)?

**Method.** The `preview` probe builds an `ExoPlayer` with `ProgressiveMediaSource.Factory({ ContentDataSource(ctx) }, DefaultExtractorsFactory())`, diagnostics off, the video surface of a 1 920 × 1 920 `ImageReader`, prepares (no `play`) and waits for the first image, for three sources (`match720p30`, `rot90_1280x720p30`, `port720x1280p24`) and two reader formats (`YUV_420_888`, whose pixels the main process can read, and `PRIVATE`), under a `FileObserver` on every app directory and an inventory diff, followed by a root `find /data -newer` over a marker.

**Results.**
- **API 35** (2026-09-25, `results/api35/2026-09-25/preview.txt`, `preview-rootfind.txt`; repeated on 2026-10-04 with the luma range, `results/api35/preview.txt`, `preview-rootfind.txt`): a frame arrived in all 6 cases both times (YUV: mean luma 106–110; `PRIVATE`: no planes, as expected); **0 `FileObserver` events, 0 inventory changes**; the root search found only `/data/system/package-dex-usage.pb` (ART's bookkeeping) the first time and nothing the second.
- **API 29** (2026-10-03 `PRIVATE` only and 2026-10-04 YUV on the standard boot, `results/api29/preview.txt`, `preview-yuv.txt`; 2026-10-04 both formats on the GLES 3 boot, `results/api29gles/preview.txt`, `preview-rootfind.txt`): a frame arrived in every case (12 of 12); **0 events, 0 inventory changes**; the root search over all of `/data` listed **nothing**. (An earlier note in the spike attributed a YUV crash on API 29 to the emulator's `gralloc`; it does not reproduce: the YUV preview works, and the crash seen in the seek probe was ART's JIT, §2.)
- **Orientation, both levels:** the image arrives in the **coded orientation**. For the rotated source ExoPlayer reports `videoSize` 720 × 1 280 with `unappliedRotationDegrees` 0, but the image is 1 280 × 720: the player applies the rotation as a transform of the surface, which an `ImageReader` ignores, so the rotation the main process must apply is the track's `Format.rotationDegrees`, not `unappliedRotationDegrees`.
- **Range, which differs by level** (`lumaMin`/`lumaMax` over the picture; the full-range sources code luma 0..255 when decoded into a buffer, V-M17): API 35 hands the coded values to the `ImageReader` (0..255), API 29 converts them to limited range on the way (16..235, for every source and output tried, the API 29 decoder having set the legacy BT.601 dataspace `0x102` on the surface). A preview that assumed one range would show the other level's pictures with crushed or washed-out tones.

**Verdict: CONFIRMS** the preview path on API 29 and 35 (one frame, no file written anywhere; API 37 has no image here, §25), with two facts the implementation must follow.

**Normative correction (S0-19, precision).** §6.2, video preview sentence: "… renders it into an `ImageReader` surface (`YUV_420_888`); the image arrives in the coded orientation (ExoPlayer applies the rotation as a surface transform, which an `ImageReader` ignores, and reports `unappliedRotationDegrees` 0) with a luma range that differs by level (S0: the coded values on API 35, limited range on API 29 for the same full-range source), so the main process converts YUV to RGB with the range and matrix of the image itself (`Image.getDataSpace()` on API 33+; on API 29–32 the range S1's emulator test pins per level; the reference phones are an S0b checklist line), turns its own pixels by the video track's `Format.rotationDegrees` (S0 V-M23, API 29 and 35), then scales, compresses and canonicalises them". §15.7: the preview test uses the rotated source and a full-range source, and checks the preview's orientation by content and its black and white levels.

---

## 24. V-M24: the canonical stream parameters (D29)

**Question (C.3).** Do `Presentation.createForWidthAndHeight(…, LAYOUT_SCALE_TO_FIT)`, `FrameDropEffect(30)`, `SonicAudioProcessor` at 48 kHz and a stereo `ChannelMixingAudioProcessor` produce exactly 1 280 × 720 or 720 × 1 280, ≤ 30 fps and 48 kHz stereo on API 29, 35 and 37, for landscape and portrait sources; and how is a portrait source coded?

**Method.** `Transcoder.Mode.DESIGN` is §8.3's configuration (forced encoding, H.264 + AAC-LC 128 kbit/s, 2 Mbit/s, `Presentation` 1 280 × 720 or 720 × 1 280 by the displayed orientation, `FrameDropEffect.createDefaultFrameDropEffect(30f)`, `SonicAudioProcessor.setOutputSampleRateHz(48 000)`, a `ChannelMixingAudioProcessor` with a matrix for every input count 1 … 8, HDR tone-mapping, diagnostics off, `ContentDataSource` only, `GhostMuxer`). Sources made on the emulator by the platform's own encoders and `MediaMuxer` (`SourceMaker`): `land1080p60` (1 920 × 1 080, 60 fps, 44.1 kHz mono), `port720x1280p24` (coded 720 × 1 280, 24 fps, 48 kHz 5.1), `rot90_1280x720p30` (coded 1 280 × 720 with a 90° rotation, the way phones store portrait video), `vga640x480p30` (22.05 kHz stereo) and the 720p30 matching source. The two portrait sources ran three ways: the design as written; with the rotation forwarded by `GhostMuxer` (`orientfix`, see below); with `Transformer.Builder.setPortraitEncodingEnabled(true)`. Outputs walked with `mediatool mp4` (dimensions from `avc1` and `tkhd`, the `tkhd` matrix, every video sample duration, the audio sample entry and ASC).

**Results** (API 35, `results/api35/transcode-save.txt`, `transcode-fixes.txt`, `mp4-report.txt`).

| Source | Output video | Frame rate (sample durations, 90 kHz) | Output audio |
|---|---|---|---|
| 1 920 × 1 080, 60 fps | 1 280 × 720, rotation 0 | 180 frames in 5.97 s, **every duration 3 000 (30.000 fps)** | 48 000 Hz, 2 ch, AAC-LC (ASC `0x1190`) |
| 640 × 480, 30 fps | 1 280 × 720 (scaled to fit, bars) | 30.000 | 48 000 Hz, 2 ch (from 22 050 Hz) |
| 1 280 × 720, 30 fps | 1 280 × 720 | 30.000 | 48 000 Hz, 2 ch |
| coded 720 × 1 280, 24 fps, 5.1 | **coded 1 280 × 720, `tkhd` rotation 0: displayed sideways** (design as written) / 1 280 × 720 + rotation 90 (`orientfix`) / coded 720 × 1 280, rotation 0 (portrait encoding on) | 24.000 (every duration 3 750; kept, not raised) | 48 000 Hz, 2 ch (from 6) |
| 1 280 × 720 + rotation 90, 30 fps | **coded 1 280 × 720, rotation 0: displayed sideways** / 1 280 × 720 + rotation 90 (`orientfix`) / coded 720 × 1 280 (portrait encoding on) | 30.000 | 48 000 Hz, 2 ch |

Two defects of the design text appeared:
1. **The rotation is lost.** With portrait encoding off (Transformer's default), Transformer codes a portrait output as landscape 1 280 × 720 and passes the rotation as `Format.rotationDegrees = 90` to `Muxer.addTrack`. It never offers an `Mp4OrientationData` to `addMetadataEntry` (V-M3), so `GhostMuxer` as §8.3 writes it ("forwards nothing except `Mp4OrientationData`") emits rotation 0 and every portrait video plays sideways. Media3's own `InAppFragmentedMp4Muxer.addTrack` creates `new Mp4OrientationData(format.rotationDegrees)` itself (1.11.1 bytecode); `GhostMuxer` must do the same (`orientfix`: `tkhd` matrix of 90°, ExifTool `Rotation` 90).
2. **Down-mixing more than two channels needs GHOST's own matrices.** `ChannelMixingMatrix.createForConstantGain(n, 2)` throws for every `n` from 3 to 8 in 1.11.1 ("Default channel mixing coefficients for 3->2 are not yet implemented", likewise 4 … 8). The probe supplies an explicit matrix: for 6 channels (FL FR FC LFE BL BR) `L = (FL + 0.7071·FC + 0.7071·BL) / 2.414`, `R` symmetric, LFE dropped; other counts alternate channels between left and right with gain `2/n`. With it the 5.1 source left as 48 kHz stereo.

Both portrait codings are possible on API 35. Transformer's default (landscape coding plus a rotation) presents every encoder with one orientation, which is what Media3 defaults to; `setPortraitEncodingEnabled(true)` codes 720 × 1 280 there and needs no rotation entry.

**API 29** (the GLES 3 boot of §1, 2026-10-04, `results/api29gles/transcode-save.txt`, `transcode-fixes.txt`, `mp4-report.txt`): every row of the table is reproduced with `OMX.google.h264.encoder` (1 280 × 720 from 1 920 × 1 080 at 60 fps with every sample duration 3 000, 24 fps kept, VGA scaled to fit, 48 kHz stereo from 44.1 kHz mono, 22.05 kHz and 5.1 with the explicit matrix, the same `createForConstantGain` exceptions for 3 … 8 channels), and both defects with it: the design as written leaves rotation 0 (sideways), `orientfix` writes the 90° matrix. **Portrait encoding fails the geometry on API 29:** with `setPortraitEncodingEnabled(true)` both portrait sources came out **612 × 1 088** (the software encoder does not take 720 × 1 280, and Transformer's encoder fallback picked the largest supported size of the same aspect ratio). The landscape coding with a rotation is the only one that yields the canonical geometry on both levels.

**Verdict: CORRECTS** the design: on API 29 and 35 the parameters are produced exactly (1 280 × 720 displayed landscape or, with the rotation, portrait; 30.000 fps from 60; rates below 30 kept; 48 kHz stereo from 22.05/44.1 kHz and from mono or 5.1) once two defects of §8.3 are fixed and portrait encoding stays off; HDR tone-mapping could not be exercised (no HDR source or 10-bit encoder on the emulators), and API 37 has no image (§25).

**Normative correction (S0-20).**
1. §8.3 `GhostMuxer` point 1: replace "`addMetadataEntry` forwards nothing except `Mp4OrientationData` with 0/90/180/270 and one `Mp4TimestampData` …" by "`addMetadataEntry` forwards nothing; `GhostMuxer` itself adds one `Mp4TimestampData` with constant times at construction and, in `addTrack` for the video track, one `Mp4OrientationData(format.rotationDegrees)` when that is 0, 90, 180 or 270 (anything else fails the export), which is what Media3's `InAppFragmentedMp4Muxer.addTrack` does: Transformer passes the rotation only as `Format.rotationDegrees` (S0 V-M24; without it every portrait video plays sideways)."
2. §8.3 Transformer configuration and D29: "a portrait source is coded as 1 280 × 720 with a 90° (or 270°) `tkhd` matrix: `setPortraitEncodingEnabled(false)`, Transformer's default, set explicitly (S0 V-M24: with portrait encoding on, API 29's encoder produced 612 × 1 088, a non-canonical size, through Transformer's encoder fallback); the manifest's `width` × `height` are the **displayed** geometry, i.e. the walker's `avc1` dimensions turned by the `tkhd` matrix; the walker accepts exactly the matrices of 0°, 90°, 180° and 270° and exactly the coded size 1 280 × 720 (every S0 output with portrait encoding off had it, the 640 × 480 source included, scaled to fit), so an encoder fallback size fails the send `NON_CANONICAL` instead of shipping."
3. §8.3 audio processors: "the `ChannelMixingAudioProcessor` gets an explicit matrix for every input count 1 … 8 (`ChannelMixingMatrix.createForConstantGain(n, 2)` exists only for `n ≤ 2` in 1.11.1): 5.1 as ITU-R BS.775 without LFE, other counts alternating left/right at gain 2/n; the matrices are constants of `GhostTranscoder` with a unit test, and an input above 8 channels is refused (`UNSUPPORTED_SOURCE`)."
4. §15.7 stream-parameter row and PM-M26: add "a 5.1 and a 4-channel source" and "a rotated (90°) and a coded-portrait source, checked for the displayed orientation (the first frame's content, not only the dimensions)".

---

## 25. Not done on this workstation, and why

| Item | Why not here | Where it is closed |
|---|---|---|
| API 37 for V-M4, V-M5, V-M17, V-M18, V-M23, V-M24 (C.3 names API 29, 35 and 37) | no API 37 system image or AVD on this workstation (only `ghost-dm-api29` and `ghost-dm-api35`); downloading one was not part of this slice | the `media-emulator` job (§15.6) once an API 37 image is in the runner set; until then the S0b device checklist on an API 37 phone |
| API 30–32 task snapshots (V-M20), the photo picker on API 30–34 and 36 (V-M21), DocumentsUI on 30–32 | no images for those levels here | the emulator job's §15.8 scan per level (S0-16, S0-17), or the checklist |
| arm64 throughput (V-M9) | the emulators are x86_64, where `chacha20`, `poly1305` and `sha2` take x86_64 SIMD backends; no arm64 device attached | S0b on the reference mid-range phone |
| Live Tor transfer times (V-M10) | no GHOST relay reachable as an onion service (staging relays are an owner action) | S0b with staging relays |
| Reference encoders' SEI and AAC elements (V-M12), their overshoot and key-frame spacing (V-M22, V-M2) | hardware encoders exist only on phones; the emulators have software encoders, deterministic, so repeated runs add nothing | S0b on the gate devices (with S0-8's tooling) |
| MTE at run time (V-M15) | no MTE hardware (x86_64 emulators, no MTE phone attached) | S0b on an MTE device (S0-11) |
| Isolated-process cost on a phone (V-M18) | emulator processes start on emulated CPUs of a loaded host; the numbers do not transfer | S0b, against Q-S2's criterion |
| f2fs file times and the birth time (V-M16) | both emulators use ext4 for `/data`; API 29's toybox prints `?` for `stat %w`, and the raw inode was not read | S0b on the reference phones |
| HDR tone-mapping (V-M17, V-M24) | no HDR source and no 10-bit HEVC encoder on the emulators | S0b on a phone that records HDR |
| V-M2's content check on API 29 | the API 29 decoder's YUV images do not decode to frame indices with the probe's block reader (an image-layout difference it does not handle); API 29 rests on timestamps, API 35 has the content check | S1's seek test (S0-2 point 5) on the emulator job |
| AAC elements after the first (V-M12) | `mediatool` reads only the first element of each raw data block | S0b tooling (S0-8) |
| V-M22's 20 transcodes per level | the emulators' encoders are deterministic (two CBR runs of each 160-s source gave byte-identical lengths), so 10 long exports on API 35 and 3 long plus 8 short on API 29 carry the information; the 20-run variance question exists only on hardware encoders | S0b |
| Linux/KVM emulator runs | this workstation is Windows with WHPX; the CI's Linux runners were not used for this slice | the first `media-emulator` job run |
| An external review of this evidence | not part of this slice | the lead's review before merging the corrections |

---

## Appendix R. The two sessions, and what moved between them

(An appendix, not §26: inside this document "§n" always means `faza11-media.md` §n.)

The first session (2026-09-25) ran every API 35 check and part of API 29 and was interrupted before its results were checked. The second (2026-10-03 … 2026-10-04) completed every check that can run here (all of API 29, V-M22, and a repeat of several API 35 checks), compared each number in this document with the files it cites, and followed up what the first session had left open. First-session reports that a later run replaced are kept under `results/api*/2026-09-25/`.

**Re-run on API 35 in the second session, and reproduced.** V-M4 (all eight orientations, identical), V-M5 (every decode outcome; timings moved, below), V-M6 (identical output sizes), V-M8 (all tests, after the fix below), V-M19 (identical apart from PIDs and timings), V-M20's native crash (79, then 81 canary copies in the `.pb`), V-M21 and V-M11 (the same URI, grant flags and stream hash), V-M23 (2026-10-04, with the luma range). **Run on API 35 in the first session only** (cited with that date): V-M1, V-M2, the exports behind V-M3, V-M17 and V-M24 (ExifTool read them in the second session), V-M9, V-M13, V-M16, V-M20's snapshots. Their API 29 counterparts all ran in the second session; V-M22 ran in the second session only.

**Moved, and why.**
1. *Timings under load* (V-M5, V-M18): the second session ran while other builds held the host at 97–100 % CPU. The 100 MP decode on API 29 went from 284.5 ms to 606 ms; the isolated-process medians from 199 to 511 ms (API 29) and from 479 to 836 ms (API 35). Both sessions are reported; none of these numbers is a phone's.
2. *The vector generator reused a nonce* (V-M8): `key_env_out` and `key_env_in` were sealed under one state key and one fixed nonce. Fixed (`wrap_nonce_in` differs, and a test asserts it), the vector file regenerated (217 lines, SHA-256 `e0ea7a82…0ed5`), the JDK replay updated; 145/145 values and 15/15 refusals afterwards.
3. *An empty root search is not a clean one* (V-M1, V-M23): the first session's API 29 root searches came back empty without proof that `adbd` ran as root. `run-all.sh`'s `rootfind` now refuses to report unless `whoami` answers `root` and ends a complete listing with an explicit line; the API 29 checks were re-run with it on the GLES 3 boot.
4. *API 29 could not transcode* (V-M1 and everything built on transcodes): the ES 2.0 boot fails every export with `eglChooseConfig failed`. Booting the same image with `-feature GLESDynamicVersion` gives ES 3.0, and the API 29 halves of V-M1, V-M3, V-M17, V-M22 and V-M24 were run that way (`results/api29gles/`; `run-all.sh` takes `29gles` as the level label so that those reports stay apart from the ES 2.0 ones).
5. *A crash attributed to the wrong cause* (V-M2, V-M23): the first session noted that API 29's `gralloc` killed the probe when a decoder's YUV image was locked, and ran the API 29 player and preview probes with `PRIVATE` images. The YUV preview works on API 29 (6 of 6 YUV frames over both API 29 boots); the crash is ART's JIT aborting in `PackElfFileForJIT` for the debuggable probe (`results/api29/seek-player-yuv-jit-abort.txt`), avoided by AOT-compiling it. The README and the probe's comments were corrected.
6. *The picker on API 29* (V-M21): two attempts failed for reasons of the method, not of the platform: DocumentsUI opened on an empty "Recent" root that the UI driver did not navigate, and later a DocumentsUI instance left in the probe's task received the pick for a dead requester. The script now force-stops DocumentsUI first and navigates by the root list; after that, two runs completed a pick each.
7. *A stalled export* (V-M22): one VBR export of a 160-s source stopped without an error; its re-run completed. Recorded as a finding (S0-18 point 3), not discarded.
8. *The coded luma range* (V-M17): the first session could only show that the colour fix changed the colour description. The second added a buffer decoder to the probe (`luma`), which showed that the fix converts the pixels on API 35 and that API 29 mislabels limited-range pixels as full range without it.
9. *Probe additions in the second session* (all evidence tooling): `luma` (V-M17); `lumaMin`/`lumaMax` in `preview`; `picked.bin` written after the V-M11 observation; the source maker's fallback without profile and colour keys for API 29's encoder (`encoderSpecs`, `makeVideoWithFallback`); `vm20-crash.sh` (tombstones, dropbox, bug report); `exif-oracle.sh`; `vm22-summary.sh`; `why-kept.pro` for R8's keep reasons; the picker script's shared-storage listing.
10. *Shared storage and the bytes handed over* (V-M21, V-M11): the first picker runs hashed only the picker-side packages and system records. The last API 29 run and the 2026-10-04 API 35 run also listed every file written to shared storage during the pick and kept the bytes the probe received, which found the thumbnails in `Pictures/.thumbnails` on both levels, the photo picker's zero-filled placeholders under `.transforms/synthetic` (with those of the 2026-09-25 pick still in the AVD's data partition nine days later), and the photo picker's zeroed GPS fields behind the "other SHA-256" that every API 35 pick had shown.
11. *The preview's range* (V-M23): the 2026-10-04 API 35 preview (with `lumaMin`/`lumaMax`) showed that API 35 hands the coded full-range values to the `ImageReader` where API 29 converts them to limited range, so S0-19 asks for the image's own range instead of a fixed one.
12. *API 29's encoder key frames* (V-M2, V-M12, V-M22): the 160-s exports on API 29 showed five IDR frames each, so the encoder's own spacing (about 32 s on average) replaces "one per export" for long videos; the fragment bound of S0-2 point 6 was set from it.
