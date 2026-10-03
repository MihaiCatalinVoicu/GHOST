# Phase 11 slice S0 — evidence tooling (not product code)

This directory is **evidence tooling** for the S0 checks of `docs/design/faza11-media.md`
(§17.1 rows S0a/S0b, Appendix C.3 checks V-M1 … V-M24). The results are in
`docs/design/faza11-s0-evidence.md`. Nothing here is product code: it is not part of the ghost
Cargo workspace (its crates have their own `[workspace]` and lock files), not part of
`ghost/android` (its Gradle build has its own `settings.gradle.kts`), not scanned by any gate
under `ghost/scripts/gates` (they read `ghost/android`, `client-core`, `relay`, `issuer`), and no
artifact built here ships. It is the Phase 11 counterpart of Phase 9's
`ghost/client-core/dm-spike`. Its fate is the same: S1 re-implements what it proves in
`ghost-client-media` under review; the scripts that turn into gates move to `ghost/scripts/gates`.

## Layout

| Path | What it is |
|---|---|
| `rust/` | crate `ghost-media-spike`: a reference implementation of the media object of design §3–§4 (`src/format.rs`), the §3.9 vector generator (`src/vectors.rs`, output `vectors/media_object.txt`), the `aead-stream` 0.6.0 oracle and the RFC 8439 / RFC 5869 vectors (`tests/oracle.rs`), the class, Padmé, sealer and §3.4 attack tests (`tests/rules.rs`), and `mediatool` (`src/bin/mediatool.rs`): MP4/fMP4 box walker, SEI and AAC element counts, source-NAL comparison, GHOST `mfra` builder, JPEG marker walker and the §8.2 canonicaliser, seal/open benchmark |
| `rust/crashlib/` | `libghost_spike_crash.so` (x86_64): a JNI function that crashes with registers pointing into a caller buffer (V-M20 tombstones) |
| `jvm/MediaVectors.java` | an independent JDK implementation (JCA ChaCha20-Poly1305, RFC 5869 HKDF) that replays `rust/vectors/media_object.txt` |
| `android/probe/` | the probe app `org.ghost.spike.media` (self-instrumenting debug APK): every emulator probe (`Probes.kt`), the isolated service of §9.2 (`IsoService.kt`, `IsoClient.kt`), `GhostMuxer` and the Transformer configuration of §8.3 (`GhostMuxer.kt`, `Transcoder.kt`), the source generator (`SourceMaker.kt`), the `mfra`/`tfdt` tools (`Mp4Mini.kt`), the V-M20 and V-M21 activities |
| `android/r8probe/` | a minimal app in two flavours (`base`, `media`) built as R8-shrunk releases (V-M7, V-M14) |
| `scripts/` | `probe.sh` (one probe), `run-all.sh` (every probe on one emulator), `vm20-snapshots.sh` + `count-pattern.ps1` (task snapshots), `vm21-picker.sh` (picker residues) |
| `results/` | the reports the evidence document quotes (text only); `work/` (git-ignored) holds pulled media |

## Environment (the owner's Windows workstation)

Git Bash; JDK 17; Rust 1.98.1 (`ghost/rust-toolchain.toml`) with `x86_64-linux-android`;
cargo-ndk 4.1.2; Android SDK with NDK 30.0.16248370, build-tools 37, platform 37, emulator and the
AVDs `ghost-dm-api29` / `ghost-dm-api35` (x86_64 AOSP images, userdebug, WHPX); Perl (Git's) for
ExifTool 13.55 (`Image-ExifTool-13.55.tar.gz` from the ExifTool SourceForge project, SHA-256
`5f4c81d34ad406538c2871ad72dbfceb5d9b412b2f16cbbeb4d712d270846667`, unpacked outside the
repository; a test oracle only, never linked or shipped).

```
export CARGO_TARGET_DIR='C:\Users\<user>\AppData\Local\Temp\ghost-target-p11-s0'
export ANDROID_HOME='C:\Users\<user>\AppData\Local\Android\Sdk' ANDROID_SDK_ROOT="$ANDROID_HOME"
export ANDROID_NDK_HOME="$ANDROID_HOME\ndk\30.0.16248370"
export PATH="$PATH:/c/Users/<user>/AppData/Local/Android/Sdk/platform-tools"
```

## Commands

Rust (from `rust/`):

```
cargo test --release -- --nocapture          # vectors current, oracle, RFC vectors, rules, attack table
GHOST_WRITE_VECTORS=1 cargo test --release --test vectors   # regenerate vectors/media_object.txt
cargo build --release                         # mediatool for the host
cargo ndk -t x86_64 build --release --bin mediatool          # mediatool for the emulator (V-M9 half)
(cd crashlib && cargo ndk -t x86_64 -o ../../android/probe/src/main/jniLibs build --release)
$CARGO_TARGET_DIR/release/mediatool bench     # host seal/open throughput of a 50 MiB object
```

JDK replay (from this directory): `java jvm/MediaVectors.java rust/vectors/media_object.txt`.

Android (from `android/`; build `crashlib` first):

```
./gradlew --no-daemon :probe:assembleDebug
./gradlew --no-daemon :r8probe:assembleBaseRelease :r8probe:assembleMediaRelease
./gradlew --no-daemon :r8probe:dependencies --configuration mediaReleaseRuntimeClasspath
```

Emulator (one at a time on port 5576, as the Phase 9 device suites ran, F9 §22.32):

```
$ANDROID_HOME/emulator/emulator.exe -avd ghost-dm-api35 -port 5576 -no-window -gpu swiftshader_indirect \
    -no-snapshot -noaudio -no-boot-anim -memory 4096 -cores 4
until [ "$(adb -s emulator-5576 shell getprop sys.boot_completed | tr -d '\r')" = 1 ]; do sleep 5; done
bash scripts/run-all.sh 35 --sources generate --long     # API 35 makes the sources (AV1 encoder)
bash scripts/vm20-snapshots.sh 35 && pwsh -File scripts/count-pattern.ps1 results/api35/vm20/*.jpg results/api35/vm20/*.png
bash scripts/vm21-picker.sh 35 work/api35/src/orient6.jpg
adb -s emulator-5576 emu kill
# then ghost-dm-api29, with the API 35 sources pushed (identical inputs):
bash scripts/run-all.sh 29 --sources push --long
```

A single probe: `bash scripts/probe.sh <api> <probe> [-e key value ...]` with a probe from
`Probes.run` (`env`, `sources`, `transcode`, `seek`, `orient`, `iso`, `isoTiming`, `unguarded`,
`crash`, `compress`, `play`, `mtime`, `preview`, `bench`, `pick`, `inventory`, `clean`).

Traps (as in F9 §22.32): a device path argument needs `MSYS_NO_PATHCONV=1` for that one `adb`
command (the scripts do it); never `adb kill-server`; if a boot loops under host load, raise the
emulator process priority. Isolated-service instance names must match `[a-zA-Z0-9_.]+`.
