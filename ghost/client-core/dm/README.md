# `ghost-client-dm` — DM cryptography (Phase 9)

The GHOST direct-message cryptography below the session layer: derivations, the contact card,
the four seal modes, the X-Wing intro layer, binding v3, the L0 codec, safety numbers and state
wrapping. Normative design: `docs/design/faza9-dm.md` §2–§9, as corrected by §21, §22 and the
S0′ evidence of `docs/design/faza9-s0-evidence.md`.

Slice **S4a** delivered the crate **without Olm**. Slice **S4b** adds `src/olm/`: the throwaway
accounts of §2.2 (the MSC3814 dehydrated pickle GHOST encodes itself), the session calls of §8.1
with the value semantics of §7.9, the stored state with the first-seen sidecar of §7.7 point 4,
and the two pickle-layout reads of §2.1 (`chainPosition`, `sessionPrune`) — the single recorded
deviation from "public API only", every drift of which is `STATE_CORRUPT`.

## What the crate guarantees about itself

- **No clock.** Every time value is an argument (`binding_minute`, `now_minute`). This is what
  makes the deterministic host/Android equivalence fixture of design §15.9 item 7 possible and
  what keeps T13 and T33 executable.
- **No network, no async runtime, no logging.** Gates `no-logging.sh` and (from S4b) G-R4 and
  G-R8 check it; the crate has no `log`, `tracing`, `std::net` or `std::time` use.
- **One source of randomness, and it is the OS CSPRNG.** `pq::fill_random` calls
  `rand::rngs::SysRng`, which is `getrandom`'s own reader, so §9.2's "encapsulation randomness
  from the OS CSPRNG" holds literally and the custom-backend routing of §22.8.10 point 7 reaches
  every byte this crate draws. Every production seal entry point draws its own salt there (R-S4);
  the `*_with` variants a vector or the equivalence fixture replays take the salt, nonce or KEM
  randomness as an argument instead, so the same call is reproducible.
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
  X-Wing keys of §22.8.2 on both the key and the ciphertext side, the L0 codec and the sender
  reserve of §21.11 point 3, the wrap bindings of §22.8.3, safety numbers, and the T35 provenance
  assertions.
- **Seeded parser property runs (R-C4, §15.2): 10⁶ inputs per parser per run**, over
  `codec::decode` and the TLV value decoders, `zbase32::decode`, the pair/provisional body parser
  and the intro inner parser (both reached directly, without paying a decapsulation per input),
  `card::parse`/`card::parse_link` and `bundle::parse`. No run may panic, over-read or return an
  untyped error. The count is `GHOST_DM_PROPERTY_INPUTS` (default 10⁶); the whole `--lib` suite
  runs in about 21 s on the CI host at that default. For the two parsers that verify an Ed25519
  signature the 10⁶ inputs vary in length, so the signature path is reached by the rare
  exact-length input and a further `10⁶ / 1000` exact-length mutants cover it; both records are
  fixed-length and additionally have an exhaustive single-bit mutation test, which is stronger
  than sampling for them.
- `tests/golden.rs`: the golden Olm pickles of design §15.2 item 2 under
  `tests/golden/vodozemac-<version>/`. They are **loaded, not regenerated**: Olm draws random base
  and ratchet keys inside the library, so the drill is the one §2.8 names — load the committed
  pickles with the pinned version, decrypt the messages each side had not read, continue both
  ways, and check the pinned `chainPosition` and `sessionPrune` outputs (G-R7). Regenerate at a
  pin change only, with `GHOST_DM_GOLDEN_WRITE=1`, into the new version's directory, keeping the
  old one until the upgrade drill has run against it.
- `tests/key_schedule.rs`: the Olm key-schedule oracle of §15.2 item 3. It re-derives
  `HKDF(salt = 0x00, M, "OLM_KEYS", 80)` and decrypts GHOST's own ciphertext with AES-256-CBC,
  checking the **8-byte** V1 MAC, with `M` exported through vodozemac's `low-level-api` (dev graph
  only). It catches the configuration misuse the library's own tests cannot see.
- `tests/state_models.rs`: **EM-1** (sessions) and **EM-2** (seal modes), enumerated exhaustively
  by breadth-first search over canonicalised states. MC-19 ("newest decrypt wins") is run as a
  substituted rule and must break a property. PR scale is two user sends per side;
  `GHOST_DM_EM_SENDS` with `GHOST_DM_EM_BUDGET` takes it to the design's six for a gate run.
- `tests/xwing_kat.rs`: the X-Wing draft-06 vectors and a differential test against RustCrypto
  `x-wing` 0.1.0 (dev graph only).
- `tests/vectors.rs`: generates and checks `protocol/test-vectors/dm_derive.txt`, `dm_seal.txt`,
  `dm_content.txt`, `dm_bundle.txt` and `dm_safety_number.txt`. After a deliberate change, rerun
  with `GHOST_DM_VECTORS_WRITE=1` and review the diff. The files are self-describing
  `key = value` text so an independent implementation replays them without reading this crate;
  design §15.2 assigns that replay to the Kotlin/JDK implementation, which lands with
  `:crypto-bridge` in S4b.

## Effect on the shipped client's dependency graph

Adding this crate to the workspace re-resolved **one** edge of `ghost/Cargo.lock`: `tempfile`
3.27.0 requires `getrandom >=0.3.0, <0.5` and now resolves to `getrandom 0.4.3` instead of
`0.3.4`. `THIRD_PARTY_NOTICES-client-net.txt` therefore lost the `getrandom 0.3.4` component
(421 → 420) and renumbered its licence texts; no other name-and-version pair in the lock changed.

The first record of this change said that "`getrandom 0.4.3` entered the lock with the DM stack",
which is **wrong**: `main` already carried 0.2.17, 0.3.4 and 0.4.3, and `ghost-client-net` already
reached 0.4.3 through `rand 0.10.2`. The real change is the `tempfile` edge alone. It is kept
rather than pinned back: fewer `getrandom` majors in the shipped graph is what §22.8.10 point 7
wants, since every major has to be routed through the deterministic world backend, and
`getrandom 0.3.4` remains in the lock for the crates that still require it.

## Decisions this slice had to make, and why

- **The result-code wire bytes.** Design §2.6 names the closed code list but fixes no numbering,
  and the JNI reply is `code(1) || TLV fields`. `result.rs` is the numbering, including the codes
  only the S4b Olm facade can produce — the list is closed, so adding one later would change the
  surface. `DmResultCodesTest` (S4b) asserts it together with the library mapping table.
- **`card::ghost1` builds the whole FR-1.3 identity string.** Design §3.3 writes
  "`ghost1 = z32(SHA-256(identity_pk))`", which names the hash the string carries. The project's
  own parser, `org.ghost.identity.GhostIdentity` (FR-1.3), accepts only
  `"ghost1" || z-base-32(version(1) ‖ SHA-256(identity_pk)(32) ‖ checksum(4))`, 66 characters, and
  rejects a bare 52-character hash on length, prefix, version and checksum. The crate produces the
  parseable form, so nothing this codebase calls `ghost1` is refused by this codebase; the §3.3
  sentence is the one to reword in S14. `dm_derive.txt`'s `ghost1` line carries the new value.
- **The T35 provenance assertion is always compiled, the check is not.** Design §9.3 puts the
  provenance tag in test builds; here every seal key carries its tag in every build (an enum
  beside 32 bytes) and only the assertion is behind `cfg(any(test, feature = "provenance"))`.
  Carrying the tag everywhere is what lets one code path serve both, and it is strictly stronger
  than the design asks.

## Deferred, with the reason

- **`cargo-fuzz` targets (design §9.5 M-8, §16.2 `dm-fuzz`).** `cargo-fuzz` needs a nightly
  toolchain and libFuzzer's C++ runtime; this host has only the pinned `1.98.1` toolchain and no
  `cargo-fuzz`, so the targets would not build or run here. The seeded parser property runs above
  (10⁶ inputs per parser per run, over every parser of the crate) and the exhaustive mutation
  tests of `card.rs` and `bundle.rs` cover the same inputs deterministically in the meantime.
- **ML-KEM-768 known-answer tests (design §9.2 "Tests", §15.2).** The FIPS 203 / ACVP vector files
  are not on this host and are not fetched here. What stands in their place is recorded and
  checked, not assumed: `the_ml_kem_halves_are_pinned_by_the_x_wing_vectors` asserts that the
  X-Wing draft-06 vectors pin the ML-KEM-768 encapsulation key (bytes 0–1 183 of `pk`) and
  ciphertext (bytes 0–1 087 of `ct`) byte for byte through the combiner, and
  `ghost_and_rust_crypto_agree_on_valid_inputs` is a differential test against RustCrypto's
  independent ML-KEM-768. That is weaker than a direct KAT on decapsulation of an **invalid**
  ciphertext (only implicit rejection exercises it), so the item stays open for S4b rather than
  closed here.
- **The X-Wing draft-10 vectors and the byte comparison of `tests/vectors/xwing-draft06.json`
  with the draft-06 Appendix text.** Both need the IETF documents. Draft-06 and draft-10 are
  wire-identical (design §9.2), so what is outstanding is a provenance check, not a behaviour
  check; the file's provenance is recorded and its SHA-256 is asserted.
- **Grapheme-cluster counting for reactions.** The codec checks that a reaction body is the
  target `message_id` plus at most 32 bytes of valid UTF-8; counting grapheme clusters would need
  a Unicode segmentation dependency that no ADR approves, so it stays with the caller that
  renders them.
