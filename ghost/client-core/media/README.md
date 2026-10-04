# `ghost-client-media` — the GHOST media object (Phase 11, slice S1)

The format, the sealer and reader state machines, the codecs and the canonical-format walkers of the
Phase 11 design (`docs/design/faza11-media.md`, revision 4: §3, §4.1, §8.2, §8.3, §13.1; §22.2 for
what S1 built and decided). Pure Rust: **no JNI, no I/O, no clock, no logging, no randomness, no
state** (the test feature `nonce-registry` aside). Slice S2 links it into `ghost-client-dm`, which
exports it as the closed JNI class `MediaNative` (§13.2) and wraps `K_f` into `key_env` (§4.2).

| Module | What |
|---|---|
| `consts`, `class` | §3.1's constants, the eleven size classes of §3.6 |
| `labels`, `keys` | the seven strings of the format (no one a prefix of another, S0-6); `K_p`, `K_m`, `commit` from the caller's `K_f` and `object_id`; `op_id` (§6.4) |
| `stream` | STREAM chunks in `aead-stream`'s `StreamBE32` layout (§3.3) |
| `manifest`, `descriptor` | the 65 536-byte manifest blob with the key commitment (§3.5); the L0 kind 0x05 body (§4.1, R-D3) |
| `sealer`, `reader` | §3.7's discipline (CS-M1: one seal per index, the last flag on `n − 1` only, a one-chunk lookahead, the walker before every seal); §3.4's checks (CS-M2), the in-order validation pass and random-access reads that expose nothing on refusal |
| `sniff` | the source allowlist of §6.1 (JPEG, PNG, static WebP, ISO-BMFF without HEIF/AVIF brands) |
| `jpeg` | the canonical JPEG profile and `jpegCanonicalize` (§8.2), streaming |
| `fmp4`, `sps` | the canonical fMP4 profile (S0-2, S0-3, S0-13, S0-20, S0-22), streaming, with the `mfra` builder; the H.264 SPS walked in full |

Untrusted bytes cannot make it panic: outside tests the crate denies `unwrap`, `expect`, `panic`,
indexing and unchecked arithmetic (`clippy::indexing_slicing`, `clippy::arithmetic_side_effects`), and
`#![forbid(unsafe_code)]`. Secrets (`FileKey`, `PayloadKey`, `ManifestKey`, `KeySlot`) are zeroised
on drop and never render in `Debug`; every plaintext buffer the crate owns is `Zeroizing`.

## Tests

```
cargo test -p ghost-client-media                     # unit, goldens, vectors, oracle, properties, hostile, sweep
GHOST_WRITE_VECTORS=1 cargo test -p ghost-client-media --test vectors --test fmp4_vectors   # rewrite media_*.txt
GHOST_MEDIA_PROPERTY_OBJECTS=10000 GHOST_MEDIA_FLIPS=4096 cargo test --release -p ghost-client-media --test properties
GHOST_MEDIA_SWEEP=full cargo test --release -p ghost-client-media --test sweep
cargo test --release -p ghost-client-media --test timing -- --ignored --nocapture   # §15.1's per-chunk cost
bash scripts/ci/media-mutants.sh [ms01-… …]          # the S1 mutants of mutants/*.patch (default: all)
```

The vector files are `protocol/test-vectors/media_{object,descriptor,sniff,jpeg,fmp4}.txt`; the JDK
replay of the first four is `android/media/src/test/kotlin/org/ghost/media/vectors/`
(`./gradlew --no-daemon :media:testDebugUnitTest`). The goldens the walker must accept are
`protocol/test-vectors/media-goldens/media3-1.11.1/`.

## Gates (G-M7)

`media-crate-purity.sh` (sources and manifest), `no-logging.sh` (with every client-core crate),
`rust-client-allowlist.sh` and `rust-feature-policy.sh` (the media clauses), `media-rust-no-logging.sh`,
`media-vendored-clock-log.sh` (with its baseline) and `rust-license-headers.sh` (the client-net graph of
`licenses/graphs.txt` lists the crate ahead of S2's link).
