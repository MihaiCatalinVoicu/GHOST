# `ghost-client-dm` — DM cryptography (Phase 9)

The GHOST direct-message cryptography below the session layer: derivations, the contact card,
the four seal modes, the X-Wing intro layer, binding v3, the L0 codec, safety numbers and state
wrapping. Normative design: `docs/design/faza9-dm.md` §2–§9, as corrected by §21, §22 and the
S0′ evidence of `docs/design/faza9-s0-evidence.md`.

Slice **S4a** delivers the crate **without Olm**. An Olm message (L1) is opaque bytes here. The
session layer, the throwaway accounts, the closed JNI surface, the `jni-bridge` feature and the
vodozemac dependency arrive in **S4b**, which is also when `ghost-client-net` takes this crate as
a dependency and the client allowlist (G-R1), the third-party notices and G-R6 start covering it.

## What the crate guarantees about itself

- **No clock.** Every time value is an argument (`binding_minute`, `now_minute`). This is what
  makes the deterministic host/Android equivalence fixture of design §15.9 item 7 possible and
  what keeps T13 and T33 executable.
- **No network, no async runtime, no logging.** Gates `no-logging.sh` and (from S4b) G-R4 and
  G-R8 check it; the crate has no `log`, `tracing`, `std::net` or `std::time` use.
- **One source of randomness.** `pq::fill_random`. Every operation a vector replays takes its
  salt, nonce or KEM randomness as an argument instead, so the same call is reproducible.
- **Pure Rust, JVM-testable.** Android Keystore is Android-only, so the crate never touches it:
  state wrapping takes the unwrapped `StateKey` as an argument and the Keystore wrapper stays in
  Kotlin (`:crypto-bridge`, S4b). That seam is the only thing between this crate and a JVM test.

## Building

The libcrux build scripts decide `simd128`/`simd256` in `build.rs` **without**
`cargo:rerun-if-env-changed`, so the `[env]` block of `ghost/.cargo/config.toml` is not enough on
its own (evidence V-6 §6.3). Every client build is preceded by

```
cargo clean -p libcrux-ml-kem -p libcrux-sha3 -p libcrux-intrinsics [--target <triple>] --release
```

which also covers CI target directories restored from caches, and gate G-R3 reads the
`cargo:rustc-cfg` lines of the build it guards.

## Tests and vectors

```
cargo test -p ghost-client-dm
```

- `src/**` unit tests: derivations and the label prefix rules, the card codec (every single-byte
  mutation and every length refused), the seal modes at every bucket, the low-order and invalid
  X-Wing keys of §22.8.2, the L0 codec with a seeded property run, the wrap bindings of §22.8.3,
  safety numbers, and the T35 provenance assertions.
- `tests/xwing_kat.rs`: the X-Wing draft-06 vectors and a differential test against RustCrypto
  `x-wing` 0.1.0 (dev graph only).
- `tests/vectors.rs`: generates and checks `protocol/test-vectors/dm_derive.txt`, `dm_seal.txt`,
  `dm_content.txt`, `dm_bundle.txt` and `dm_safety_number.txt`. After a deliberate change, rerun
  with `GHOST_DM_VECTORS_WRITE=1` and review the diff. The files are self-describing
  `key = value` text so an independent implementation replays them without reading this crate;
  design §15.2 assigns that replay to the Kotlin/JDK implementation, which lands with
  `:crypto-bridge` in S4b.

## Decisions this slice had to make, and why

- **The result-code wire bytes.** Design §2.6 names the closed code list but fixes no numbering,
  and the JNI reply is `code(1) || TLV fields`. `result.rs` is the numbering, including the codes
  only the S4b Olm facade can produce — the list is closed, so adding one later would change the
  surface. `DmResultCodesTest` (S4b) asserts it together with the library mapping table.
- **The T35 provenance assertion is always compiled, the check is not.** Design §9.3 puts the
  provenance tag in test builds; here every seal key carries its tag in every build (an enum
  beside 32 bytes) and only the assertion is behind `cfg(any(test, feature = "provenance"))`.
  Carrying the tag everywhere is what lets one code path serve both, and it is strictly stronger
  than the design asks.

## Deferred, with the reason

- **`cargo-fuzz` targets (design §9.5 M-8, §16.2 `dm-fuzz`).** `cargo-fuzz` needs a nightly
  toolchain and libFuzzer's C++ runtime; this host has only the pinned `1.98.1` toolchain and no
  `cargo-fuzz`, so the targets would not build or run here. The parser property run in
  `codec.rs` (`the_decoder_never_panics_on_seeded_inputs`) and the exhaustive mutation tests of
  `card.rs` and `bundle.rs` cover the same inputs deterministically in the meantime.
- **The X-Wing draft-10 vectors and the byte comparison of `tests/vectors/xwing-draft06.json`
  with the draft-06 Appendix text.** Both need the IETF documents. Draft-06 and draft-10 are
  wire-identical (design §9.2), so what is outstanding is a provenance check, not a behaviour
  check; the file's provenance is recorded and its SHA-256 is asserted.
- **Grapheme-cluster counting for reactions.** The codec checks that a reaction body is the
  target `message_id` plus at most 32 bytes of valid UTF-8; counting grapheme clusters would need
  a Unicode segmentation dependency that no ADR approves, so it stays with the caller that
  renders them.
