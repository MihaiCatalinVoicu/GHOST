# Phase 11 slice S0 — evidence tooling (not product code)

This directory is **evidence tooling** for the S0 checks of `docs/design/faza11-media.md`
(§17.1 rows S0a/S0b, Appendix C.3 checks V-M1 … V-M24). The results are in
`docs/design/faza11-s0-evidence.md`. Nothing here is product code and nothing built here ships:

- it is not part of the ghost Cargo workspace (its two crates have their own `[workspace]` tables
  and lock files, so `ghost/Cargo.lock`, the client allowlist, the crypto pins and cargo-deny are
  untouched);
- it is not part of `ghost/android` (its Gradle build has its own `settings.gradle.kts`, wrapper
  and dependency set; the product's version catalog and dependency verification are untouched);
- no gate under `ghost/scripts/gates` scans it (their roots are `ghost/android`, `client-core`,
  `relay` and `issuer`, `scripts/gates/common.sh`).

It is the Phase 11 counterpart of Phase 9's `ghost/client-core/dm-spike`, and its fate is the same:
S1 re-implements what it proves in `ghost-client-media` under review, the scripts that turn into
gates move to `ghost/scripts/gates`, and the directory is then deleted.

## Layout

| Path | What it is |
|---|---|
| `rust/` | crate `ghost-media-spike`: a reference implementation of the media object of design §3–§4 (`src/format.rs`), the §3.9 vector generator (`src/vectors.rs`, output `vectors/media_object.txt`), the `aead-stream` 0.6.0 oracle and the RFC 8439 / RFC 5869 vectors (`tests/oracle.rs`), the class, Padmé, sealer and §3.4 attack tests (`tests/rules.rs`), and `mediatool` (`src/bin/mediatool.rs`): MP4/fMP4 box walker, SEI and AAC first-element counts, source-unit comparison, GHOST `mfra` builder, JPEG marker walker and the §8.2 canonicaliser, canary search, seal/open benchmark |
| `rust/crashlib/` | `libghost_spike_crash.so` (x86_64): a JNI function that crashes with registers pointing into a caller buffer (V-M20 tombstones); built into `android/probe/src/main/jniLibs` (git-ignored) |
| `jvm/MediaVectors.java` | an independent JDK implementation (SunJCE ChaCha20-Poly1305, RFC 5869 HKDF) that replays `rust/vectors/media_object.txt` |
| `android/probe/` | the probe app `org.ghost.spike.media` (self-instrumenting debug APK): every emulator probe (`Probes.kt`), the isolated service of §9.2 (`IsoService.kt`, `IsoClient.kt`), `GhostMuxer` and the Transformer configuration of §8.3 (`GhostMuxer.kt`, `Transcoder.kt`), the source generator (`SourceMaker.kt`), the `mfra`/`tfdt` tools (`Mp4Mini.kt`), the V-M20 and V-M21 activities |
| `android/r8probe/` | a minimal app in two flavours (`base`, `media`) built as R8-shrunk releases (V-M7, V-M14); `why-kept.pro` is used only with `-PwhyKeeping` |
| `android/mteprobe/` | a manifest with a per-process `memtagMode` for an isolated `:mdec` (V-M15, manifest level) |
| `scripts/` | `probe.sh` (one probe), `run-all.sh` (the emulator steps), `vm20-snapshots.sh` + `count-pattern.ps1` (task snapshots), `vm20-crash.sh` (tombstones, dropbox, bug report), `vm21-picker.sh` (picker residues), `exif-oracle.sh` (ExifTool's T43 reading), `vm22-summary.sh` (bitrate overshoot) |
| `results/` | the reports the evidence document quotes (text, plus the V-M20 snapshot images and the few files the picker runs pulled); `results/api*/2026-09-25/` holds first-session reports that a later run replaced; `results/api29gles/` the API 29 runs on the OpenGL ES 3 boot; `results/api29/vm21-first/`, `vm21/` and `vm21-stale-task/`, `results/api35/vm21-2026-10-03/` and `vm21/` the picker runs; `work/` (git-ignored) holds pulled media and bug reports |

## Environment (the owner's Windows workstation)

Git Bash; JDK 17; Rust 1.98.1 (`ghost/rust-toolchain.toml`) with `x86_64-linux-android`;
cargo-ndk 4.1.2; Android SDK with NDK 30.0.16248370, build-tools and platform 37, emulator 37.1.11
and the AVDs `ghost-dm-api29` / `ghost-dm-api35` (x86_64 AOSP images, userdebug, WHPX); Git's Perl
for ExifTool 13.55 (`Image-ExifTool-13.55.tar.gz` from the ExifTool SourceForge project, SHA-256
`5f4c81d34ad406538c2871ad72dbfceb5d9b412b2f16cbbeb4d712d270846667`, unpacked outside the
repository; a test oracle only, never linked or shipped). Python is not needed.

```
export CARGO_TARGET_DIR='C:\Users\<user>\AppData\Local\Temp\ghost-target-p11-s0'
export ANDROID_HOME='C:\Users\<user>\AppData\Local\Android\Sdk' ANDROID_SDK_ROOT="$ANDROID_HOME"
export ANDROID_NDK_HOME="$ANDROID_HOME\ndk\30.0.16248370"
export PATH="$PATH:/c/Users/<user>/AppData/Local/Android/Sdk/platform-tools"
export MEDIATOOL=/c/Users/<user>/AppData/Local/Temp/ghost-target-p11-s0/release/mediatool.exe
export NATIVE_MEDIATOOL=/c/Users/<user>/AppData/Local/Temp/ghost-target-p11-s0/x86_64-linux-android/release/mediatool
export EXIFTOOL="perl /path/to/Image-ExifTool-13.55/exiftool"
```

## Commands

Rust (from `rust/`):

```
cargo test --release --locked -- --nocapture   # vectors current, oracle, RFC vectors, rules, attack table
cargo tree --locked -e normal,dev               # V-M8: aead-stream beside chacha20poly1305 on one aead
GHOST_WRITE_VECTORS=1 cargo test --release --locked --test vectors   # regenerate vectors/media_object.txt
cargo build --release --locked --bin mediatool                   # mediatool for the host
cargo ndk -t x86_64 build --release --locked --bin mediatool     # mediatool for the emulators (V-M9)
(cd crashlib && cargo ndk -t x86_64 -o ../../android/probe/src/main/jniLibs build --release --locked)
"$MEDIATOOL" bench; "$MEDIATOOL" bench-stream   # host seal/open of a 50 MiB object
```

JDK replay (from this directory): `java jvm/MediaVectors.java rust/vectors/media_object.txt`.

Android (from `android/`; build `crashlib` first):

```
./gradlew --no-daemon :probe:assembleDebug :mteprobe:assembleDebug
./gradlew --no-daemon :r8probe:assembleBaseRelease :r8probe:assembleMediaRelease
./gradlew --no-daemon :r8probe:dependencies --configuration mediaReleaseRuntimeClasspath
./gradlew --no-daemon -PwhyKeeping :r8probe:assembleMediaRelease   # V-M14: R8's keep reasons
```

Emulator (one at a time, port 5576, `-read-only` so that another session may run the same AVD;
the Phase 9 device-suite practice of F9 §22.32):

```
$ANDROID_HOME/emulator/emulator.exe -avd ghost-dm-api35 -port 5576 -read-only -no-window \
    -gpu swiftshader_indirect -no-snapshot -noaudio -no-boot-anim -memory 4096 -cores 4
until [ "$(adb -s emulator-5576 shell getprop sys.boot_completed | tr -d '\r')" = 1 ]; do sleep 5; done
bash scripts/run-all.sh 35 --sources generate          # API 35 makes the sources (AV1 encoder)
bash scripts/run-all.sh 35 --steps short,long          # V-M22 (about an hour; REPS=2)
adb -s emulator-5576 emu kill
# API 29 with the API 35 sources pushed (identical inputs). Booted as above, its image exposes
# OpenGL ES 2.0 under SwiftShader and Media3's video effects cannot run (V-M1), so the V-M2 golden
# comes from API 35. The player half of `seek` reads PRIVATE images there: the YUV run aborts the
# debuggable probe in ART's JIT (Android 10, `PackElfFileForJIT`), which
# `adb -s emulator-5576 shell cmd package compile -m speed -f org.ghost.spike.media` avoids.
SEEK_ARGS="-e player 0" SEEK_PLAYER_ARGS="-e readerFormat private -e playerSeeks 20" \
bash scripts/run-all.sh 29 --golden-from work/api35/out
adb -s emulator-5576 emu kill
# The same API 29 image with OpenGL ES 3.0: the same boot line plus `-feature GLESDynamicVersion`.
# The level label `29gles` keeps its reports apart (results/api29gles/, work/api29gles/).
bash scripts/run-all.sh 29gles --steps install
adb -s emulator-5576 shell cmd package compile -m speed -f org.ghost.spike.media
SEEK_ARGS="-e player 0" SEEK_PLAYER_ARGS="-e readerFormat private -e playerSeeks 20" \
bash scripts/run-all.sh 29gles --steps env,glinfo,sources,vm1,goldens,seek,analyse,preview,short
TAG=long bash scripts/probe.sh 29gles sources -e set long
TAG=longvbr bash scripts/probe.sh 29gles transcode -e set longvbr   # API 29's encoder has no CBR
# V-M17's coded luma range: first copy work/api35/out/match720p30__DESIGN.mp4, ...__DESIGN_bt709.mp4,
# match720p30_709__DESIGN.mp4 and the same three of work/api29gles/out/ into the app's files/src/ as
# vm17_<35|29>_<DESIGN|DESIGN_bt709|709src>.mp4 (adb push to /data/local/tmp, cp, chown to the
# app's uid, restorecon), then
TAG=vm17 bash scripts/probe.sh 29gles luma -e files match720p30.mp4,match720p30_709.mp4,vm17_35_DESIGN.mp4,vm17_35_DESIGN_bt709.mp4,vm17_35_709src.mp4,vm17_29_DESIGN.mp4,vm17_29_DESIGN_bt709.mp4,vm17_29_709src.mp4
bash scripts/vm21-picker.sh 29 work/api35/src/orient6.jpg   # V-M21/V-M11 on DocumentsUI
adb -s emulator-5576 emu kill
# API 35 again (2026-10-04): the preview with the luma range, and the picker run with the
# shared-storage listing and the picked-bytes comparison.
bash scripts/run-all.sh 35 --steps install,sources,preview
bash scripts/vm21-picker.sh 35 work/api35/src/orient6.jpg
adb -s emulator-5576 emu kill
```

`run-all.sh` uses the level argument only as a label for `results/api<label>/` and
`work/api<label>/`; `vm20-*.sh` and `vm21-picker.sh` take the numeric level.

Host analyses of what was pulled: `bash scripts/exif-oracle.sh work/api35/canon/*.jpg work/api35/out/*.mp4`
(needs `EXIFTOOL` and `MEDIATOOL`), `bash scripts/vm22-summary.sh results/api35/transcode-*.txt`,
`"$MEDIATOOL" mp4|jpeg|nalcmp|canary …`.

A single probe: `bash scripts/probe.sh <api> <probe> [-e key value ...]` with a probe from
`Probes.run` (`env`, `sources`, `transcode`, `seek`, `orient`, `iso`, `isoTiming`, `unguarded`,
`crash`, `compress`, `play`, `mtime`, `preview`, `luma`, `bench`, `pick`, `inventory`, `clean`).

Picker residues (V-M21, V-M11): `bash scripts/vm21-picker.sh <api> work/api35/src/orient6.jpg`
(numeric level; it force-stops DocumentsUI first, pushes the picture under a fresh name, drives the
picker with uiautomator, hashes the picker-side packages and system records before and after, and
lists what was written to shared storage). Crash residues (V-M20):
`bash scripts/vm20-crash.sh <api> 1` (native), `2` (Java), `3` (SIGSEGV); task snapshots:
`bash scripts/vm20-snapshots.sh <api>`.

Traps (as in F9 §22.32): a device path argument needs `MSYS_NO_PATHCONV=1` for that one `adb`
command (the scripts do it); never `adb kill-server` and never kill an emulator another session
started; if a boot loops under host load, wait and retry. Isolated-service instance names must
match `[a-zA-Z0-9_.]+`. Do not edit `run-all.sh` while it runs (bash reads it as it goes).
