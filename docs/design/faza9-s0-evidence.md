# GHOST Phase 9, slice S0′: measurement probe and spike evidence

| Field | Value |
|---|---|
| Design | `docs/design/faza9-dm.md` (revision 2026-09-16 with §22.8), §17.1 row S0′, Appendix C checks V-1 … V-16 |
| Scope of this document | V-1, V-2, V-3, V-4, V-5, V-6, V-7, V-8, V-9, V-10, V-12, V-14, V-15, V-16 (V-11, V-13 and V-17 belong to other slices) |
| Date | 2026-09-16; every check re-run and every number verified on 2026-09-19 (Appendix V) |
| Branch | `p9-spikes` (worktree of `D:/Forum`), base `cc24c5c` |
| Toolchain | Rust 1.98.1 (`rust-toolchain.toml`), cargo-ndk 4.1.2, Android NDK 30.0.16248370, JDK 17.0.20.1 (Microsoft build), cargo-deny 0.20.2 |
| Host | Windows 11 Pro 10.0.26200, Intel Core Ultra 9 275HX (24 cores, 24 threads), 95.4 GiB RAM; the four self-hosted CI runners (WSL2) were busy during the whole first session (host CPU load 99–100 % when sampled), so every timing recorded there is an upper bound |
| Pins measured | vodozemac 0.11.0 (`.crate` SHA-256 `ba935af0…2574`, tag commit `db1b3482…`) and 0.10.0 (`b98bf83c…ae5b`, `bb39ec65…`), `default-features = false`; libcrux-kem 0.0.9 with libcrux-ml-kem 0.0.10, libcrux-sha3 0.0.10, libcrux-curve25519 0.0.8, portable-only; RustCrypto x-wing 0.1.0 (test oracle); ed25519-dalek 2.2.0; BouncyCastle bcprov-jdk18on 1.85.2 |
| Code | `ghost/client-core/dm-spike` (crate `ghost-dm-spike`) and the temporary probe patch `ghost/client-core/dm-spike/size-probe/size-probe.patch` |
| Status | Evidence for the lead. **This document does not edit `faza9-dm.md`; each section ends with the exact normative correction to merge.** |

**How to read.** One section per check: method, commands, numbers, conclusion, normative correction. §0 summarises the values to freeze and the corrections; §15 lists what this slice could not do on this host and why; Appendix V records the verification re-run and the corrections it produced. Paths are relative to `D:/Forum`. `vz:` cites vodozemac 0.11.0 sources in the local cargo registry, `kem:` libcrux-kem 0.0.9 `src/kem.rs`.

---

## 0. Summary

### 0.1 Values to freeze

| Constant | Value | Evidence |
|---|---|---|
| `O_MAX` | **1 664 B** (unchanged) | measured worst intro PreKey envelope overhead 1 606 B on both pins (V-3); margin 58 B at 64 KiB, 60 B at 4 and 16 KiB; SessionConfig V2 would use 1 630 B |
| Body capacity per bucket | 2 220 B (4 KiB), 14 508 B (16 KiB), 63 660 B (64 KiB) (unchanged) | V-3 |
| Olm PreKey overhead over L0 | ≤ 179 B at 4 and 16 KiB, ≤ 181 B at 64 KiB | V-3, 3 120 outputs per pin |
| Olm normal overhead over L0 | ≤ 73 B at 4 and 16 KiB, ≤ 74 B at 64 KiB | V-3 |
| `SESSION_STATE_MAX` | **65 536 B** (unchanged) | measured worst JSON pickle 36 685 B on both pins (V-4); margin 28 851 B (44.0 %) |
| X-Wing sizes | public key 1 216 B, ciphertext 1 120 B, seed 32 B, shared secret 32 B | V-6 vectors |
| MSC3814 pickle | 105 B with a fallback key, 73 B without | V-1 |
| Gap hold | enabled; expected index from the stored session | V-7 |
| DM stack in `libghost_client_net.so` | +494 992 B (arm64-v8a), +629 904 B (x86_64) with X-Wing through the slice trait | V-9 |
| Skipped-key age bound | adopted: prune at `FRESH + 2σ` = 51 d | V-15 |

### 0.2 Normative corrections (merged by the lead)

| # | Check | Sections | Correction (short) |
|---|---|---|---|
| S0-1 | V-1 | §2.2, §3.1, §15.2 | encoder layout written out; the serde `Account::from_pickle` and the doc-hidden `from_decrypted_dehydrated_device` paths forbidden; one derivation vector |
| S0-2 | V-2 | §2.6, §22.8.2 | `MismatchedSessionConfig` and a decrypt-time `NonContributoryKey` mapped; `DmResultCodesTest` becomes a compile-time exhaustive match |
| S0-3 | V-3 | §6.6, D9, RG-8 | `O_MAX` frozen at 1 664 from measurement; overhead rows corrected |
| S0-4 | V-4 | §7.9 point 4, §21.5, CS-8 | `SESSION_STATE_MAX` frozen at 65 536 with the measured 36 685 B bound |
| S0-5 | V-5 | §2.3, §2.6, §2.7, §15.1 | Windows load confirmed; exports survive both routes; a silent panic hook is mandatory; Linux load moved to the first CI run |
| S0-6 | V-6 | §2.3, §9.2, §16.1 G-R1/G-R3, §16.3, §22.8.2 | X-Wing only through the `XWing` slice trait plus an explicit ML-KEM key check (the enum API panics on short inputs); G-R3 with a clean-before-build rule (the variables do not re-run the build scripts); allowlist names confirmed; a reasoned cargo-deny advisory exception; timings |
| S0-7 | V-7 | §7.7, CS-3, Q54, §2.6 | gap hold enabled; its expected index read from the stored session; the declared loss bound restated to Olm's real rule |
| S0-8 | V-8 | §16.1 G-R4, G-R8 | baseline recorded; G-R4 scoped to the graph without `jni-bridge` |
| S0-9 | V-9 | §2.3, §2.7, §2.9, §16.1 G-R2, Q45 | measured size per ABI (+495 KB, +630 KB with the slice trait; the enum API breaks the x86_64 budget); `hpke` dropped by the linker; precomputed tables off |
| S0-10 | V-10 | §7.9 point 2, R-36 | confirmed on both pins; the consequence stated precisely |
| S0-11 | V-12 | §15.2, §16.2 | `vendor-tests` requirements and source of the suite |
| S0-12 | V-14 | §2.4, X-21, R-37, §15.2 | BouncyCastle verifies cofactored and differs from dalek strict on 33 of 53 edge vectors: X-21 artifacts verified only in Rust; the JDK replay expectations split |
| S0-13 | V-15 | §7.7 point 4, Q67, R-41, §2.6, §15.7 | age bound adopted: pinned-schema prune with a first-seen sidecar inside the wrapped state, a new JNI call, MC-30 joins (97 mutants) |
| S0-14 | V-16 | §15.9 item 7, RG-2 | harness plan |

### 0.3 The spike crate

`ghost/client-core/dm-spike` (`ghost-dm-spike`) is **not a workspace member**: it has its own `[workspace]` and `Cargo.lock`, so the product lock, `rust-client-allowlist.sh`, `rust-crypto-pins.sh` and `cargo deny` of the ghost workspace are untouched. It depends on both vodozemac pins at once (renamed `vz11`, `vz10`). Its `src/` passes `anti-placeholder.sh` and `no-logging.sh` (both scan `client-core/**/src`); the checks are its integration tests (`tests/`), JVM programs (`jvm/`) and scripts (`scripts/`). `cargo fmt --check` and `cargo clippy --all-targets -D warnings` (with `jni-host`, and with `v2-config`) are clean. **Fate: deleted in S4b.** `ghost-client-dm` re-implements the MSC3814 encoder check, the golden sizes, `FailedDecryptLeavesStateTest`, the session harness (as EM-1 and the RO/RS suites), the X-Wing wrapper and the prune under review with the pins of §2.3; the G-R8 scanner (`examples/g_r8_scan.rs`) and the portable detector (`scripts/libcrux-portable-detector.sh`) move to `ghost/scripts/gates/` with fixtures in S0′/S4a. Nothing in it is a production source.

Reproduce everything (from `ghost/client-core/dm-spike`, with `CARGO_TARGET_DIR` set outside `D:`):

```
cargo test --release -- --nocapture          # V-1, V-2, V-3, V-4, V-6, V-7, V-10, V-14 (Rust half), V-15
cargo test --release --features v2-config --test v3_v2_margin -- --nocapture
bash scripts/libcrux-portable-detector.sh --release --tests
bash scripts/v5-host-load.sh                 # V-5
bash scripts/v14-ed25519-jvm.sh              # V-14 (JDK half)
git apply ghost/client-core/dm-spike/size-probe/size-probe.patch   # from the repository root; V-8, V-9; git apply -R and git checkout ghost/Cargo.lock to undo
bash scripts/v9-size-build.sh <out> [features]
bash scripts/v8-g-r8-baseline.sh <work-dir>   # needs the patch; uses cargo tree only
bash scripts/v12-vendor-tests.sh 0.11.0      # V-12 (needs network, cmake, C++)
```

---

## 1. V-1: the dehydrated-pickle identity

**Method.** `tests/v1_dehydrated.rs`, run once per pin through a macro (the vodozemac API used is identical in both).
1. *Encoder check* (§22.8.10 point 14). For 16 fresh `Account::new()` objects that called `generate_fallback_key()` and 16 that did not, per pin: export with `to_dehydrated_device(key)`, open the ChaCha20-Poly1305 ciphertext with the key and nonce, and compare the plaintext with GHOST's own encoder (`src/msc3814.rs`, written from the MSC3814 layout) fed with secrets read from the account's **JSON pickle** (`diffie_hellman_key`, `signing_key.Normal`, `fallback_keys.fallback_key.key`), not from the export. A strict decoder re-reads the bytes.
2. *Seed-derived identity.* HKDF-SHA256 with an empty salt reproduces the pinned `messaging_seed` of `:identity` for root entropy `00 01 … 1f` (`android/identity/src/test/resources/derivation_vectors.txt`), which fixes the convention; then `oi = HKDF(m, "ghost/v1/dm/olm-identity")`, `s = HKDF(m, "ghost/v1/dm/olm-account-signing")`, a random fallback secret, GHOST-encode, seal under a fresh random key and nonce, `Account::from_dehydrated_device`. The identity keys must equal `X25519(oi)` computed by x25519-dalek 2.0.1 and `Ed25519(s)` computed by ed25519-dalek 2.2.0. A second import from the same `m` (a "restore") must give the same `OI` and the same safety number v1 (§8.4, implemented in `src/safety.rs`).
3. *Fallback secret, behaviourally.* A second `Account` creates an outbound session to `(OI, F_g)`; `create_inbound_session` on the GHOST-built account must open it; a session to another `F` must fail with `MissingOneTimeKey`. `fallback_key()` on the imported account must be empty (the import marks the key published).
4. *Refusals.* A pickle with version 2 and a truncated pickle must be refused; a JSON session pickle that does not parse is `STATE_CORRUPT`.
5. Both pins must import one GHOST pickle to the same identity keys.

**Command.** `cargo test --release --test v1_dehydrated` → 9 passed (4 per pin, 1 across pins).

**Numbers.**
- Encoder: 64 of 64 exports byte-identical (16 × {with, without fallback} × 2 pins). Layout confirmed: `u32_be(1) ‖ curve25519_secret(32) ‖ ed25519_seed(32) ‖ u32_be(0) ‖ u8(1) ‖ fallback_secret(32)` = 105 B, or `… ‖ u8(0)` = 73 B.
- Derived identity: equal on both pins; the restore gives the same `OI` and safety number.
- `fallback_key()` after the import: 0 entries on both pins. `MissingOneTimeKey` for another `F`: yes on both pins.
- Vector for `protocol/test-vectors/dm_derive.txt`: root entropy `000102…1f`, `messaging_seed = 82453de0…50cf`, **`OI = X25519(HKDF(m, "ghost/v1/dm/olm-identity")) = d80580eca7efdcd429060d7c25bb83d731943aef3cfecd947b048b72d8b00603`** (the V-5 JVM run prints the same value from the same input).

**Conclusion.** V-1 holds on 0.11.0 and 0.10.0. Two further public construction paths exist and must not be used: `Account::from_pickle(AccountPickle)` takes vodozemac's serde layout, which is undocumented and unversioned (the MSC3814 layout is specified and versioned), and `Account::from_decrypted_dehydrated_device` is `#[doc(hidden)]`, "public for fuzzing" (`vz:src/olm/account/mod.rs:576-594`).

**Normative correction (S0-1).**
1. §2.2, row "No constructor from given identity keys", append: "The pickle is `u32_be(1) ‖ curve25519_secret(32) ‖ ed25519_seed(32) ‖ u32_be(0) ‖ u8(1) ‖ fallback_secret(32)` (105 B; `u8(0)` and no secret without a fallback key, 73 B), confirmed byte for byte against `to_dehydrated_device` of 0.11.0 and 0.10.0 in S0′ (V-1). `Account::from_pickle` (serde layout) and the doc-hidden `Account::from_decrypted_dehydrated_device` are not used."
2. §3.1 and §15.2: add the vector `olm_identity_pub` for root entropy `000102…1f` = `d80580eca7efdcd429060d7c25bb83d731943aef3cfecd947b048b72d8b00603` to `dm_derive.txt` (replayed by Rust and by the independent Kotlin implementation).

---

## 2. V-2: sessions through throwaway accounts, D2b, R-SS1 … R-SS3

**Method.** `src/harness.rs` models one device's view of one contact: the pinned Olm identity, the `current` and `previous` slots (`session_id`, JSON pickle, role, `acknowledged`, `peer_bind_minute`, `retire_day`, `peer_gen_id`), the reuse set `(gen_id, session_id)` and the own bundle generations. Every Olm call goes through `src/olm.rs` with value semantics (a fresh `Session` from stored JSON per call, new JSON only on success) and throwaway accounts built from GHOST MSC3814 pickles: `sessionOutbound` from the identity without a fallback key, `sessionInbound` from the identity plus exactly the named generation's fallback secret. RECV's R7 dispatch: a PreKey message whose `session_id` matches a slot decrypts there; else an unknown `gen_id` is `drop(unknown_generation)`; else a tuple in the reuse set is `drop(replay)`; else `sessionInbound` and R-SS1 with the §22.8.4 exception. Normal messages use the two-slot trial with `DUPLICATE_OR_LOST` precedence, then R-SS2 with the §22.8.4 guards. Two switches turn the harness into mutants: `d2b = false` (MC-7′) and `age_rules = false` (MC-32). `tests/v2_sessions.rs` scripts the scenarios; library facts and codes run on both pins.

**Command.** `cargo test --release --test v2_sessions` → 8 passed.

**Results.**

| Scenario | Result |
|---|---|
| First flight of 3 PreKey messages; the first creates `current`, the second matches its `session_id`; a duplicate of the first | `DUPLICATE_OR_LOST` (D2a) |
| B's normal reply | A's slot `acknowledged`; A's next output is a normal message |
| B resets (R-SS0) and receives A's third first-flight message | `drop(replay)` (D2b); with `d2b = false` the library creates the session again (MC-7′ detected) |
| Library fact, both pins | the same PreKey message through `create_inbound_session` twice gives two sessions with the same `session_id` (fallback keys are not consumed, `vz:src/olm/account/mod.rs:324`) |
| Simultaneous first contact (R-SS3), 8 runs | both sides hold the same `current` after two round trips, and it is the smaller `session_id`; 6 of 6 messages displayed; the converged session keeps working |
| Restore of B from the same seed | `OI` reproduced; B's reconnect intro becomes A's `current` (responder), A's own session its `previous`; A's reply reaches B; A's pre-restore message to B's lost session is `UNDECRYPTABLE` (declared loss, L7-D12) |
| §22.8.4 late first flight (old intro bound at minute 1 000, new at 2 000, processed new first) | the old session becomes `previous`, its PreKey re-send decrypts there without a swap (guard a), my reply reaches the contact; with `age_rules = false` the old session wins and my reply is `UNDECRYPTABLE` at the contact (MC-32 detected) |
| A third, older first flight while both slots hold newer responder sessions | `drop(stale_session)`, reuse set unchanged |
| §22.8.2 rule 1, both pins, every small-order u-coordinate of the 8-torsion subgroup and the non-canonical encodings u = p, p + 1 | a PreKey message whose inner ratchet key was replaced and re-authenticated with the sender's chain key (`src/schedule.rs`, Olm's key schedule, as a malicious sender can do) is accepted by `create_inbound_session`, which decrypts it; the new session's first `encrypt` then fails (`EncryptionError::NonContributoryKey` → `INVALID_SESSION`); GHOST's contributory pre-check returns `INVALID_KEY` first |
| Error codes, both pins | low-order fallback key or identity at `create_outbound_session` → `INVALID_KEY`; another expected identity → `IDENTITY_MISMATCH`; a generation without the named fallback key → `MISSING_KEY`; a flipped ciphertext byte → `UNDECRYPTABLE`; the same message twice → `DUPLICATE_OR_LOST`; a forward gap of 2 001 (sender index moved in its pickle) → `GAP_TOO_BIG`; a pickle that does not parse → `STATE_CORRUPT` |

**Conclusion.** Sessions interoperate through throwaway accounts on both pins; D2b is necessary (the library alone accepts replays) and sufficient in the scripted cases; R-SS1 … R-SS3 with the §22.8.4 rules converge and detect MC-7′ and MC-32. Two library errors are not named by the §2.6 table: `SessionCreationError::MismatchedSessionConfig` (a PreKey message of another session version) and `DecryptionError::NonContributoryKey` at `decrypt` (a normal message under a low-order ratchet key; `DoubleRatchet::advance` fails). Neither enum is `#[non_exhaustive]` on either pin, so a `match` without a wildcard is exhaustive at compile time (`src/olm.rs`: `creation_code`, `decryption_code`, `encryption_code`). Not covered here: the exhaustive enumeration EM-1 (S4b), KC3b, `WrapBindingTest`, PQ6 (V-17).

**Normative correction (S0-2).**
1. §2.6 table, row 14 (`sessionInbound`): "`UNDECRYPTABLE` (also `MismatchedSessionConfig`: a PreKey message of another session version)"; row 13 (`decrypt`): "`UNDECRYPTABLE` (also a non-contributory ratchet key of a normal message)".
2. §22.8.2 rule 4, last sentence, replace "`DmResultCodesTest` enumerates every variant …" by: "`DmResultCodesTest` is a compile-time exhaustive `match` without a wildcard over `SessionCreationError`, `DecryptionError`, `EncryptionError` (none is `#[non_exhaustive]` in 0.11.0) and libcrux-kem's `Error`, so a variant added at a bump fails the build (G-R7 drill); its runtime half checks the mapping table."

---

## 3. V-3: Olm overheads and `O_MAX` (measurement probe, RG-8)

**Method.** `src/sizes.rs` and `tests/v3_v4_probe.rs`, per pin. A real session pair gives an initiator (outputs are PreKey messages) and a responder after one received message (outputs are normal messages). For every plaintext length in `0 … 64` and in `[C(B) − 64, C(B)]` for each bucket (`C(B) = B − 1 664`: 2 368 … 2 432, 14 656 … 14 720, 63 808 … 63 872), and for every sending chain index in {0, 127, 128, 2¹⁴, 2²¹, 2²⁸, 2³⁵, 2⁴², 2⁴⁹, 2⁵⁶, 2⁶³, 2⁶⁴ − 2} (every protobuf varint length from 1 to 10 bytes; the index is set in the stored pickle, a serde layout both pins share), the probe records `|L1| − |L0|`. The class of a length is the smallest bucket with `len ≤ B − 1 664`. The fixed parts of §6.2, §6.4 and §6.6 are added, with the X-Wing ciphertext length taken from libcrux (V-6). `tests/v3_v2_margin.rs` repeats the 64 KiB worst case with `SessionConfig::version_2()` (feature `experimental-session-config`, spike only, forbidden in shipped graphs).

**Commands.** `cargo test --release --test v3_v4_probe -- --nocapture`; `cargo test --release --features v2-config --test v3_v2_margin -- --nocapture`.

**Numbers (identical for 0.11.0 and 0.10.0; 3 120 outputs per pin).**

| Bucket class | PreKey max | PreKey max, index < 2²⁸ | Normal max | Normal max, index < 2²⁸ | Worst intro envelope overhead | Worst pair or provisional overhead | Slack at the class edge (intro) |
|---|---|---|---|---|---|---|---|
| 4 KiB | 179 | 173 | 73 | 67 | 49 + 1 376 + 179 = 1 604 | 49 + 5 + 73 = 127 | 60 B |
| 16 KiB | 179 | 173 | 73 | 67 | 1 604 | 127 | 60 B |
| 64 KiB | 181 | 175 | 74 | 68 | 49 + 1 376 + 181 = **1 606** | 49 + 5 + 74 = **128** | 58 B |

- PreKey = version 1 ‖ three 34-byte key fields ‖ tag 1 ‖ length varint (2 B up to 16 KiB, 3 B at 64 KiB) ‖ inner normal message. Normal = version 1 ‖ ratchet-key field 34 ‖ index tag 1 + varint 1 … 10 ‖ ciphertext tag 1 + length varint 2 … 3 ‖ PKCS#7 padding 1 … 16 ‖ MAC 8.
- SessionConfig V2 at 64 KiB, index 2⁶⁴ − 2: PreKey 205, normal 98; worst intro 1 630 B, still ≤ 1 664 (margin 34 B).
- Capacities with `O_MAX = 1 664` and `L_class = 52 + |body| + 160`: 2 220 B, 14 508 B, 63 660 B; the probe asserts that a body at each capacity fits after sealing in intro and in pair mode.

**Conclusion.** The construction of §6.6 was right to the byte, except that its "≤ 181" and "≤ 74" rows hold only in the 64 KiB class (3-byte length varints). `O_MAX = 1 664` is confirmed by measurement with 58 B of margin at the tightest class, enough for a move to SessionConfig V2 (+24 B). The chain index needs 10 varint bytes only past 2⁶³ messages on one chain; the bound still counts them.

**Normative correction (S0-3).**
1. §6.6 table: replace the two Olm rows by "Olm PreKey message over its L0: ≤ 179 (4 and 16 KiB), ≤ 181 (64 KiB; 3-byte length varints)" and "Olm normal message over its L0: ≤ 73 (4 and 16 KiB), ≤ 74 (64 KiB)", both "measured on 0.11.0 and 0.10.0 over every chain-index varint length (V-3)"; the `O_MAX` row reads "**1 664** (frozen in S0′: measured worst intro overhead 1 606 B at 64 KiB, 1 604 B at 4 and 16 KiB; SessionConfig V2 would need 1 630 B)".
2. D9 and RG-8: the word "provisional" is removed from `O_MAX`.
3. §6.6 "Golden sizes": the S0′ probe set (lengths `0 … 64` and `[C(B) − 64, C(B)]`, twelve chain-index varint classes, both output kinds) is the golden-size set re-run at every bump (G-R7).

---

## 4. V-4: the worst-case session pickle and `SESSION_STATE_MAX`

**Method.** `src/pickle_bound.rs`. A real responder session is driven to the structural maximum: the peer sends 41 messages per chain and only the last is decrypted (40 skipped keys stored), the responder answers so the peer starts a new chain, five times; the responder's last output leaves its sending ratchet active with a parent key. The driven JSON pickle is then **widened**: every 32-byte array to bytes `255`, every `index` and `Known` counter to `18446744073709551615`. The widened pickle must load with `Session::from_pickle` and serialise back to the same JSON value and length, so it is a reachable encoding of the pinned layout; a length formula written from the layout (`analytic_bound`) cross-checks it. A 0.10.0 pickle is loaded by 0.11.0.

**Command.** `cargo test --release --test v3_v4_probe v4 -- --nocapture`.

**Numbers.**

| Pin | Driven shape | Driven JSON | Widened JSON (bound) | Formula | Margin to 65 536 |
|---|---|---|---|---|---|
| 0.11.0 | 5 chains × 40 skipped keys, active ratchet with a parent key | ≈ 29.8 kB (varies) | **36 685 B** | 36 685 B | 28 851 B (44.0 %) |
| 0.10.0 | same | ≈ 29.8 kB (varies) | **36 685 B** | 36 685 B | 28 851 B (44.0 %) |

The *driven* JSON length is not a constant: the pickle holds fresh random key bytes and serde writes each byte as a decimal number, so its length depends on how many of the 1 000-odd key bytes need one, two or three digits. Four runs of the probe gave 29 818, 29 835, 29 856 and 29 879 B for 0.11.0 and 29 719, 29 796, 29 804 and 29 831 B for 0.10.0; only the order of magnitude is meaningful, and the test asserts the shape, not the length. The **widened** length is deterministic (every byte 255, every counter `u64::MAX`) and is the bound: 36 685 B on both pins, equal to `analytic_bound` to the byte.

A 0.10.0 pickle loads in 0.11.0 and re-serialises to identical bytes (the layouts are the same; `ratchet_count` and `parent_ratchet_key` exist in both).

**Conclusion.** `SESSION_STATE_MAX = 65 536` holds with 44 % margin; a peer cannot exceed 36 685 B (fixed-capacity arrays, `u64` counters). The wrapped envelope `nonce(12) ‖ ciphertext ‖ tag(16)` is then at most 36 713 B, inside the `olm_session.state_env` CHECK (29 … 65 564). Storage consequence (CS-8): at most 2 × 36 685 B per contact, 73.4 MB at `MAX_CONTACTS = 1 000` in the worst case (a live session is typically about 1 KB).

**Normative correction (S0-4).** §7.9 point 4: "`SESSION_STATE_MAX = 65 536` bytes of pickle, frozen in S0′: the largest JSON pickle of 0.11.0 and of 0.10.0 is 36 685 B (5 receiver chains × 40 skipped keys, an active sending ratchet with a parent key, every byte and counter at its longest spelling; V-4); RO6 asserts the measured bound and a fault-injected oversize." §21.5 and CS-8 cite the same number.

---

## 5. V-5: the host build in the JVM; JNI exports of `libghost_client_net.so`

**Method.** Two parts.
1. *Host load (Windows).* The spike builds as a `cdylib` with feature `jni-host` (`src/jni_host.rs`, the `ghost-dm-host` shape: byte arrays in, `code(1) ‖ payload` out, every entry under `catch_unwind`). `scripts/v5-host-load.sh` builds it for `x86_64-pc-windows-msvc`, lists the PE export table with the NDK's `llvm-objdump -p`, compiles `jvm/org/ghost/dmspike/DmHostProbe.java` with `javac --release 17`, and runs it on JDK 17: `System.load(<dll>)`, then `olmRoundTrip` (a seed-derived account receives a first message from a throwaway sender and answers it), `xwingRoundTrip` (keygen, encapsulation, decapsulation) and `panicProbe` (a 100-byte X-Wing key into `PublicKey::decode`, which panics, V-6).
2. *Exports on Android.* The probe patch links a temporary crate into `ghost-client-net` two ways: `ghost_dm_probe::export_jni!()` invoked in `jni_bridge.rs` (the route of §2.3) and a `#[no_mangle]` function defined in the dependency itself. After the release build (`strip = "symbols"`), `llvm-nm -D --defined-only` lists the dynamic exports of both ABIs.

**Commands.** `bash scripts/v5-host-load.sh`; `llvm-nm -D --defined-only <out>/<abi>/libghost_client_net.so | grep Java_org_ghost_crypto`.

**Numbers.**
- Windows: `ghost_dm_spike.dll` 1 479 680 B with three `Java_org_ghost_dmspike_DmHostProbe_*` exports; `olmRoundTrip` code 0, `OI = d80580ec…0603`, reply decrypted; `xwingRoundTrip` code 0, public key 1 216 B, secrets equal; `panicProbe` code 0xff (`INTERNAL`) and the JVM continued; JDK 17.0.20.1, Windows 11, amd64. The default panic hook wrote the panic message to stderr.
- Android: both ABIs export `Java_org_ghost_crypto_bridge_DmNative_probeOlm`, `…_probeKem` (macro) and `…_probeDirect` (dependency `#[no_mangle]`) beside the 21 existing exports.

**Conclusion.** The host build loads and runs the real ratchet and X-Wing in a JDK 17 JVM on Windows (MSVC). Both export routes survive linking and stripping on arm64-v8a and x86_64, so the §2.3 fallback ("explicit wrapper functions") is not needed; the macro stays because it keeps the closed list visible in `ghost-client-net` for G-R6. **Linux was not verified on this host** (§15). A caught panic still prints its message through the default hook, which the no-logging rule forbids for the DM graph.

**Normative correction (S0-5).**
1. §2.3, `client-core/net` row: replace "(S0′ checks that the symbols survive linking, V-5; fallback: explicit wrapper functions)" by "(V-5: macro exports and a dependency's `#[no_mangle]` exports both survive linking and `strip = "symbols"` on both ABIs; the macro is kept so the closed list stays visible in `ghost-client-net`)".
2. §2.6, first paragraph: after "Rust panics are caught (`catch_unwind`)" insert "under a silent panic hook installed once per process at library load and by `ctxOpen` (the `ghost-client-net` `jni_bridge` pattern), so no panic text reaches stderr or logcat".
3. §15.1, "S0′ blocking check V-5": "Windows MSVC verified in S0′ (V-5); Linux: the first `android` job run on the ubuntu-24.04 runner image executes `client-core/dm-spike/scripts/v5-host-load.sh` before S4b starts; if it fails, the §17.1 re-plan applies."

---

## 6. V-6: X-Wing through libcrux-kem, the graph review, the portable-only detector, timings

### 6.1 Vectors, differential test, low-order and invalid inputs

**Method.** `src/xwing.rs` wraps `libcrux-kem` 0.0.9 (`default-features = false`, `Algorithm::XWingKemDraft06`) with the rules of §22.8.2: exact lengths first, whole-key validation (the ML-KEM half through `PublicKey::decode`, the X25519 half by a contributory trial agreement), every library error typed (`INVALID_KEY` on the sealing side, `NOT_OPEN` on the opening side). `tests/v6_xwing.rs`:
1. **Draft-06 vectors.** `vectors/xwing-draft06.json` (3 vectors: `seed`, `sk`, `pk`, `eseed`, `ct`, `ss`) is a copy of `tests/test-vectors.json` of the RustCrypto `x-wing` 0.1.0 crate from the local cargo registry, which cites the draft repository's `spec/test-vectors.json` (the crate's README: "matches the draft RFC version 06"); file SHA-256 `a8726596f4c7629590f727b1bbeb483f6932292fbf5fd85c9cbb803190014f00`. For each vector: `sk` is the 32-byte seed, `key_gen_derand(seed)` gives `pk`, `encapsulate_derand(pk, eseed)` gives `ct` and `ss`, decapsulation gives `ss`.
2. **Differential test** against `x-wing` 0.1.0 (dev-dependency only): 256 random seeds and `eseed`s; public keys, ciphertexts and secrets equal, decapsulation equal.
3. **Low-order X25519 halves.** Every u-coordinate of the 8-torsion subgroup and the non-canonical encodings u = p, p + 1 (6 distinct values): in a public key, GHOST's validation refuses it, `PublicKey::decode` alone accepts it (it validates only the ML-KEM half, `kem:242-258`) and encapsulation then fails; `x-wing` accepts the key and returns a secret. In a ciphertext, decapsulation fails (`NOT_OPEN`); `x-wing` returns a secret.
4. **Invalid ML-KEM half** (a first coefficient 0xFFF ≥ q = 3 329): decode refuses it. Wrong public-key lengths (0, 32, 1 183, 1 215, 1 217) and ciphertext lengths (0, 1 119, 1 121): typed refusals. A flipped ML-KEM ciphertext byte: implicit rejection, a different secret, no error.
5. **Library panics.** `PublicKey::decode(XWingKemDraft06, bytes)` with fewer than 1 184 bytes panics (`kem:246`, slice index); `PublicKey::encapsulate_derand(seed)` with a seed shorter than 32 (ML-KEM part) or than 64 bytes panics (`kem:574`). `Ct::decode` and `PrivateKey::decode` check lengths and return errors.
6. **The slice-trait path** (`libcrux_kem::XWing` through `libcrux_traits::kem::slice::Kem`, the path §9 measures as much smaller): the three vectors (keygen from the 32-byte seed into a 1 216-byte encapsulation key and a 2 432-byte expanded decapsulation key, encapsulation from `eseed`, decapsulation); wrong lengths of the key, the randomness and the ciphertext; the six low-order X25519 halves; the invalid ML-KEM half, compared with `libcrux_ml_kem::mlkem768::validate_public_key`.

**Command.** `cargo test --release --test v6_xwing -- --nocapture` → 8 passed.

**Results.** Vectors 3 of 3; differential 256 of 256; low-order public keys and ciphertexts 6 of 6 refused by GHOST, with the documented difference to `x-wing` (libcrux errors, `x-wing` returns a secret); both panics reproduced. The slice-trait path matches the vectors, returns typed errors for every wrong length (its macro converts slices with `try_into`), fails encapsulation on all six low-order X25519 halves, and **encapsulates to an invalid ML-KEM half without complaint** (the trait implementation of `libcrux-ml-kem` 0.0.10 performs no FIPS 203 input check, `src/lib.rs:117-172`), which the explicit `validate_public_key` refuses. The draft-10 vectors were not replayed (§15).

### 6.2 Graph review (the product resolution)

**Method.** With `size-probe/size-probe.patch` applied (a temporary workspace crate `ghost-dm-probe` with vodozemac and libcrux-kem, linked into `ghost-client-net`), the lock was resolved offline against the existing `ghost/Cargo.lock` (existing versions kept), and `cargo tree --offline -p ghost-client-net -e normal --target <triple>` was compared with and without the DM features on both shipped triples; `cargo tree -e normal,build` over the probe looked for C toolchains; `cargo deny --offline check` ran with `ghost/deny.toml` (advisory database as cached locally).

**Numbers.**
- **Package names added to the shipped `ghost-client-net` graph** (not on `client-core/rust-dependency-allowlist.txt`), vodozemac 0.11.0 + libcrux-kem 0.0.9, both triples: `aead`, `block-padding`, `cbc`, `chacha20poly1305`, `hpke`, `matrix-pickle`, `matrix-pickle-derive`, `poly1305`, `serde_bytes`, `serdect`, `vodozemac`; `hax-lib`, `hax-lib-macros`, `libcrux-curve25519`, `libcrux-ecdh`, `libcrux-hacl-rs`, `libcrux-intrinsics`, `libcrux-kem`, `libcrux-macros`, `libcrux-ml-kem`, `libcrux-p256`, `libcrux-platform`, `libcrux-secrets`, `libcrux-sha2`, `libcrux-sha3`, `libcrux-traits`. This is exactly the G-R1 list of §16.1 (11 + 15 names). vodozemac 0.10.0 instead of 0.11.0 drops `hpke`, `serdect` and adds `opaque-debug`.
- **New versions of existing names** (no allowlist change, pins change), the same nine on both triples: `base16ct 1.0.0`, `base64 0.23.1`, `curve25519-dalek 5.0.0`, `ed25519 3.0.0`, `ed25519-dalek 3.0.0`, `hkdf 0.13.0`, `hmac 0.13.0`, `signature 3.0.0`, `x25519-dalek 3.0.0`. `chacha20poly1305 0.11.0` is a **new name**, already counted in the list above, not a new version of an existing one (the unpatched graph holds no `chacha20poly1305`); `curve25519-dalek-derive 0.1.1` is already in the unpatched x86_64 graph (curve25519-dalek 4.1.3's SIMD backend) and is not added by the DM stack.
- **Version sets in the shipped graph with the DM stack:** `rand {0.8.8, 0.10.2}`, `rand_core {0.6.4, 0.10.1}`, `getrandom {0.2.17, 0.4.3}`, `curve25519-dalek {4.1.3, 5.0.0}`, `x25519-dalek {2.0.1, 3.0.0}`, `ed25519-dalek {2.2.0, 3.0.0}`, `hpke 0.14.1`, `sha2 {0.10.9, 0.11.0}`, `hmac {0.12.1, 0.13.0}`, `hkdf {0.12.4, 0.13.0}`: no new `rand` major (§22.8.10 point 5 confirmed).
- **No C code:** no `cc`, `cmake`, `bindgen`, `clang-sys`, `crabgrind` or `libloading` in the probe's normal and build graph for either Android triple (they are in the lock through libcrux-platform's optional valgrind path, not in the graph); no new `links` key.
- **Licences of the added packages:** Apache-2.0 (vodozemac, matrix-pickle, every libcrux crate, hax-lib), `MIT OR Apache-2.0` / `Apache-2.0 OR MIT` (RustCrypto crates, serde_bytes, serdect), BSD-3-Clause (dalek 3/5), `MIT/Apache-2.0` (hpke, the legacy slash form, read by cargo-deny as OR). `cargo deny check`: **licenses ok, bans ok, sources ok; advisories FAILED** on `RUSTSEC-2026-0173` ("`proc-macro-error2` is unmaintained"), reached only as `proc-macro-error2 2.0.1 ← hax-lib-macros 0.3.7 (proc-macro) ← hax-lib 0.3.7 ← libcrux-intrinsics, libcrux-ml-kem, libcrux-secrets, …`: build-time code only, nothing of it is linked.

### 6.3 The portable-only detector (G-R3)

**Method.** `libcrux-ml-kem`, `libcrux-sha3` and `libcrux-intrinsics` decide `feature="simd128"` (aarch64) and `feature="simd256"` (x86_64) in their `build.rs` from `LIBCRUX_DISABLE_SIMD128/256`, **without `cargo:rerun-if-env-changed`**. `scripts/libcrux-portable-detector.sh` runs `cargo build --message-format=json` and reads cargo's `build-script-executed` messages, which cargo emits for every build script of the build, fresh or re-run, with the cfgs the compiler receives; it fails on a `simd` cfg from those three crates and on a build that contains none of them. Sequence on the host (x86_64) in one target directory: (1) build without the variables; (2) add `.cargo/config.toml` `[env]` with both variables set to `"1"` and build again; (3) `cargo clean -p libcrux-ml-kem -p libcrux-sha3 -p libcrux-intrinsics` and build; (4) override the variable to `"0"` on the command line and build.

**Results.** (1) FAIL (`feature="simd256"` from all three); (2) **FAIL: the config change did not re-run the build scripts**, the SIMD cfgs of step 1 were reused; (3) portable (3 build scripts, no simd cfg); (4) still portable: the reverse change is not picked up either. The detector reports exactly the cfgs the build used in each case. Through cargo-ndk 4.1.2, `cargo ndk -t arm64-v8a build … --message-format=json` printed no cargo messages at all (tried for V-8), so Android builds cannot use the message route; there, cleaning the three packages for the target first leaves exactly one `build/<package>-<hash>/output` file per package, whose `cargo:rustc-cfg` lines are the ones used.

### 6.4 Timings

**Method.** `host_timings` in `tests/v6_xwing.rs`, release, portable build (step 3 above), 20 batches of 100 calls each; the fastest batch is reported as the least disturbed by the CI load on the host, with the median batch beside it.

Timings are the only numbers in this document that depend on what else the host is doing, so each row carries two measurements: the first session, with the four CI runners holding the host at 99–100 % CPU, and the verification re-run of 2026-09-19 on an idle host. Neither is a device measurement; the loaded column is the upper bound the design is sized against.

| Operation | Loaded host: best / median batch | Idle host: best / median batch |
|---|---|---|
| X-Wing key generation from the seed (SHAKE-256, ML-KEM-768 keygen, X25519 base point) | 110 / 148 µs | 57 / 71 µs |
| X-Wing encapsulation with GHOST's whole-key validation (decode and ML-KEM key check, contributory trial, ML-KEM encaps, X25519 keygen and agreement, SHA3-256) | 303 / 405 µs | 135 / 167 µs |
| X-Wing decapsulation from the seed (expansion, ML-KEM decaps, X25519, SHA3-256) | 144 / 193 µs | 121 / 150 µs |
| component: ML-KEM-768 keygen / encaps / decaps (libcrux portable) | 27 / 31 / 39 µs (median 33 / 35 / 44) | 24 / 28 / 33 µs (median 25 / 31 / 33) |
| component: X25519 agreement (libcrux-curve25519, HACL) | 37 / 52 µs | 32 / 42 µs |
| component: contributory trial (x25519-dalek 2.0.1, fresh scalar) | 46 / 84 µs | 41 / 47 µs |

The SIMD build of step 1 measured the same composite operations within noise (keygen 172 µs, encapsulation 437 µs, decapsulation 299 µs as unbatched means under the same load), so the portable rule costs nothing measurable here.

**Low-end phone estimate (not a measurement).** A Cortex-A53-class phone is assumed 15–25 times slower single-threaded than this host's best batches (public single-core benchmark ratios for such SoCs against a 2025 laptop HX part; scalar 64-bit integer code). The estimate is anchored to the **loaded** column, so it stays an upper bound: keygen 1.7–2.8 ms, encapsulation 4.5–7.6 ms, decapsulation 2.2–3.6 ms. Anchored to the idle column it would be about half that, which is headroom, not a new claim. An intro open costs one decapsulation after a hint match, a first message one encapsulation, a bundle generation one keygen per week: far below the 1 s foreground budget of R-S5. The measurement on the reference low-end device stays in the device checklist (§15.10 step 9).

### 6.5 Conclusion and correction

**Conclusion.** `libcrux-kem`'s X-Wing matches draft-06 and RustCrypto's implementation on valid inputs; on invalid inputs it errors where `x-wing` returns a secret (the §22.8.2 difference, confirmed) and its enum API **panics on short inputs**, which only length checks before every call prevent (`catch_unwind` turns a panic into `INTERNAL`, which §2.6 reserves for bugs). The `XWing` slice-trait path has no such panic and is much smaller (§9), but skips the ML-KEM key check, which becomes an explicit call. The graph adds no C code, no copyleft licence, no new `rand` major and exactly the names §16.1 lists; it adds one unmaintained build-time crate. Setting the libcrux variables in `.cargo/config.toml` does not make an existing target directory portable: the CI jobs restore target directories from caches (`Swatinem/rust-cache`), so G-R3 must read the cfgs of the build it guards. The Q55 combiner is not needed.

**Normative correction (S0-6).**
1. §22.8.2 rule 3, append: "`ghost-client-dm` calls X-Wing only through `libcrux_kem::XWing` and the `libcrux_traits::kem::slice::Kem` trait (typed length errors; S0-9), after `libcrux_ml_kem::mlkem768::validate_public_key` on the first 1 184 bytes (the trait performs no ML-KEM key check) and the contributory X25519 trial. The enum API (`PublicKey`, `Ct`, `PrivateKey`) is not used: `PublicKey::decode(XWingKemDraft06, ·)` panics on fewer than 1 184 bytes and `encapsulate_derand` on a seed shorter than 64 bytes (`libcrux-kem-0.0.9/src/kem.rs:246,574`; V-6). A fuzz target covers every libcrux entry point."
2. §16.1 G-R3, replace the rule by: "The libcrux build scripts do not re-run when `LIBCRUX_DISABLE_SIMD*` change (V-6), so every client build (host and both Android triples) is preceded by `cargo clean -p libcrux-ml-kem -p libcrux-sha3 -p libcrux-intrinsics [--target <triple>] --release`, which also covers target directories restored from caches. `libcrux-portable.sh` then fails if a `cargo:rustc-cfg` line of those three packages carries `feature="simd128"` or `feature="simd256"`, or if it finds no such build: for host builds it reads the `build-script-executed` messages of the guarded `cargo build --message-format=json`; for cargo-ndk builds, which print no cargo messages, it reads the single `build/<package>-<hash>/output` file each package has after the clean. Fixture: a target directory first built without the variables and not cleaned."
3. §16.1 G-R1: "the names of §16.1 are confirmed by `cargo tree -e normal` on both shipped triples (V-6); vodozemac 0.11.0 adds no further name; 0.10.0 would add `opaque-debug` and not `hpke` or `serdect`."
4. §16.3, libcrux row, and `ghost/deny.toml`: add an advisory exception `RUSTSEC-2026-0173` with the reason "`proc-macro-error2` (unmaintained) reached only through the `hax-lib-macros` proc-macro of the libcrux graph: build-time code, nothing linked; re-review at every libcrux or hax-lib bump", recorded in ADR-36.
5. §9.2 Tests: "encapsulation and decapsulation timings: host (S0′, V-6) keygen 110 µs, encapsulation 303 µs with validation, decapsulation 144 µs (portable, upper bounds under load); low-end device estimate 2–8 ms per operation; the device measurement remains §15.10 step 9."

---

## 7. V-7: reorder loss against the 40-skipped-keys window

**Method.** `src/reorder.rs`, `tests/v7_reorder.rs`. One sender writes a burst of 60 normal messages on one receiver chain (no replies), composed every U[1 s, 10 s]. Each message is stored on the 3 relays of the set at the sender's (relay, inbox) pair events (30 s × U[0.5, 1.5], independent phases): immediately in STANDARD (store latency U[0.2 s, 3 s]); in HIGH after one `ceil_minute(compose + U[0, 10 min])` delay sampled per message, at most 8 stores per pair event (Phase 7 design §6.2). Relay variants: all honest; one relay never serves the recipient; one relay serves each blob up to 30 min late. The recipient lists each relay at its own pair events, fetches at most 8 blobs per pair event in blob-hash order (`InboxStore.dueFetches` orders by `retain_until_day, blob_hash`), and runs one consumer pass after every read event; it is online from the start, or offline until an hour after the last store. Consumer policies: Phase 7 claim order (fetch order); peek ordering (§7.7 point 1: all fetched blobs sorted by chain index); peek ordering plus the gap hold with the expected index kept in process memory (§7.7 point 2, `HOLD_MAX = 12 min`); the same with the expected index read from the stored session (the next index of the receiver chain of the message's ratchet key, 0 for an unknown key); each hold variant also with a fresh process for every pass (a background job per pass). Decryption is the real vodozemac 0.11.0 session with value semantics; a message is lost on `MissingMessageKey`. `predict_losses` replays each consumption order against a model of Olm's receiver chain written from `receiver_chain.rs` (chain position, a FIFO of 40 skipped keys, keys more than 40 behind a decrypted index never stored), and the test requires the model and vodozemac to agree on every world. 200 seeded worlds per configuration, 72 configurations.

**Command.** `cargo test --release --test v7_reorder -- --nocapture` (59 s).

**Numbers** (12 000 messages per row; the relay variants gave the same picture, the table shows the worst of the three).

| Mode, recipient | Claim order: lost (worlds with loss) | Peek: lost | Peek + memory hold | Peek + memory hold, fresh process per pass | Peek + session hold (either process model) | Largest display delay added after fetch (session hold) |
|---|---|---|---|---|---|---|
| STANDARD, online | 0 | 0 | 0 | 0 | 0 | 0.4 min |
| STANDARD, offline | 2 303 (198) | 1 470 (187) | 0 | 0 | 0 | 2.1 min |
| HIGH, online | 157 (46) | 75 (23) | 0 | **57 (20)** | 0 | 10.6 min |
| HIGH, offline | 2 238 (197) | 1 432 (184) | 0 | 0 | 0 | 2.3 min |

The model predicted the loss count of every world exactly (72 × 200 worlds). Known orders confirm the rule: index 41 first loses index 0 (never stored), and two jumps that store 45 keys lose the 5 oldest although no single jump exceeds 40.

**Conclusion.** Peek ordering alone does not protect an offline recipient, whose fetches arrive in hash order, 8 per pair event: about 12 % of a 60-message burst is lost, 0.6 % for an online HIGH recipient. The gap hold removes every loss in these worlds and adds at most 10.6 min of display delay (HIGH) and about 2 min elsewhere. Keeping the expected index in process memory is not enough: with a fresh process per pass, the first blob of a chain in each process is never held, and 0.5 % of HIGH bursts are lost; the stored session already holds the exact expected index, and reading it makes the hold restart-proof. The declared bound of §7.7 point 3 and CS-3 ("at most 40 later messages … decrypted before it") does not describe Olm: a single message 41 indices ahead loses the earlier one, and keys skipped in several steps are evicted after 40 without 40 later messages. The 5-receiver-chain limit was not exercised (single-chain bursts).

**Normative correction (S0-7).**
1. §7.7 point 2 (and Q54, default "yes, enabled"): "**Bounded gap hold (enabled; V-7).** A peeked blob of a session S under ratchet key R with chain index i is skipped (left `fetched`) until `first_seen + HOLD_MAX (12 min)`, at most once per blob per process, when i > n and some index in [n, i) is not in the peek set, where n is the next chain index of S's receiver chain for R read from S's stored state (0 when S has no chain for R). The read writes nothing (T28)." The in-memory "highest decrypted chain index per process" and the sentence "After a restart no blob is held …" are withdrawn.
2. §2.6: add JNI function 19 `chainPosition(h, contactId, sessionId, stateEnv, ratchetKey) → next_index | NEW_CHAIN` (`STATE_CORRUPT`), called during peek on the envelope of the session the recognition key names; G-R6's closed list gains it.
3. §7.7 point 3 and CS-3, replace the bound by: "A message with chain index i on receiver chain C of session S is lost if, before it is processed, (a) a message of C with index greater than i + 40 was decrypted while i had not been, (b) more than 40 keys of C were skipped after i's key was stored, (c) 5 newer receiver chains of S were created, or (d) S was deleted or retired (Olm's rule, `vz:src/olm/session/receiver_chain.rs:186-254`, `vz:src/olm/session/mod.rs:55`; model checked against vodozemac in V-7)."
4. §15.5 RO3′ and RO7 use the V-7 worlds (60-message HIGH bursts, offline recipient, a withholding and a late relay, a fresh process per pass) and require zero loss with the hold.

---

## 8. V-8: no logging, clock or network in the DM graph; the G-R8 baseline

**Method.** With `size-probe/size-probe.patch` applied, `scripts/v8-g-r8-baseline.sh` takes, for each shipped triple, (1) the package set of `cargo tree -p ghost-dm-probe -e normal` with the DM features (vodozemac 0.11.0 and the libcrux-kem X-Wing slice trait), (2) the same with `-e normal,no-proc-macro` (what is linked; the rest runs only while compiling), and (3) the enabled features of every package as built into the shipped library (`cargo tree -p ghost-client-net -f '{p}|{f}'`, resolver 2). `examples/g_r8_scan.rs` then parses the `lib` target's module tree of each package with `syn`, removes every item, impl item, statement and arm whose `#[cfg]` is false for the target (`test`, `debug_assertions`, disabled features, other architectures and operating systems; unknown predicates are kept), follows `mod` declarations including `#[path]` and `cfg_attr(…, path)`, and scans the remaining tokens, including macro invocations and `macro_rules!` bodies (comments are not tokens), for `SystemTime`, `Instant::now`, `std::time`, `chrono`, `time::`, `log::`, `tracing::`, `println!`, `eprintln!`, `dbg!`, `print!`, `eprint!` and the network names `std::net`, `TcpStream`, `TcpListener`, `UdpSocket`, `ToSocketAddrs`. `cargo:` directives of build scripts are listed separately. A crate-level check looks for logging crates in the graph (`cargo tree -i log`, `-i tracing`).

**Commands.** `git apply ghost/client-core/dm-spike/size-probe/size-probe.patch`; `bash scripts/v8-g-r8-baseline.sh <work-dir>`.

**Numbers.**
- Graph: 100 packages over both triples, 74 linked, 10 proc-macros, 16 build-time only.
- **vodozemac, hpke, matrix-pickle and every libcrux crate: 0 sites.**
- Linked sites (31), all in crates GHOST already ships: `jni` 0.21.1, 23 × `log::` (its `debug!`, `trace!`, `warn!`, `error!` calls through the `log` facade; `log` is reached **only** through `jni`, `cargo tree -i log`); `memchr` 2.8.3, 2 × `log::` inside a macro body that expands to nothing without its disabled `logging` feature; `serde_core` 1.0.229, 4 re-exports (`Duration`, `SystemTime`, `std::net`) used by serde impls; `rand` 0.10.2, a `core::time::Duration` import; `libc` 0.2.189, a `time` module re-export. No `tracing` in the graph; no clock read, socket or print in DM crypto code.
- Build-time sites (8): `libcrux-macros` (a `tracing` path inside `quote!` output for test instrumentation) and `proc-macro-crate` 3.5.0 (reads `Cargo.toml` timestamps while compiling).
- Directives: 137 `cargo:` lines in 17 build scripts; the libcrux ones are exactly the six `feature="simd128"`/`"simd256"` lines of `libcrux-intrinsics`, `libcrux-ml-kem` and `libcrux-sha3` (G-R3's mechanism).
- Unparsed files: none. Two `include!` targets are not followed and are listed as notes: `thiserror` 2.0.20 (a module generated into `OUT_DIR` at build time) and `hax-lib` 0.3.7 (`src/proc_macros.rs`, macro re-exports).
- The justified baseline is committed as `ghost/client-core/dm-spike/baseline/g-r8-baseline.txt` (every entry with its reason; 0 unjustified).
- Notices (§22.8.10 point 3): the vodozemac and libcrux `.crate` packages in the registry carry no `NOTICE` file (confirmed for vodozemac 0.11.0: `LICENSE` only; libcrux-kem 0.0.9 and libcrux-ml-kem 0.0.10: no licence file at all), so G-L1 takes their Apache-2.0 text from the SPDX snapshot. The upstream-commit `NOTICE` capture was not done here (§15).

**Conclusion.** The DM crypto graph (vodozemac 0.11.0, hpke, libcrux) adds no logging, no clock and no network code. The only logging in the linked graph comes from `jni` 0.21.1 through the `log` facade, which `ghost-client-net` already ships and for which no logger is installed (the app's Rust side never calls `log::set_logger`). G-R4 as written ("`ghost-client-dm`'s normal graph contains no `log`") fails as soon as the `jni-bridge` feature is on, because `jni` depends on `log`. A token scan counts names, not calls, so re-exports need justification; the baseline has seven justification classes.

**Normative correction (S0-8).**
1. §16.1 G-R4: "`ghost-client-dm`'s normal graph **without the `jni-bridge` feature** contains no `log`, `tracing` or `env_logger`; with `jni-bridge`, `log` is reached only through `jni` (checked with `cargo tree -i log`), and no crate of either graph installs a logger; its sources contain no `println!`, `eprintln!`, `dbg!`."
2. §16.1 G-R8: the scan is defined as in V-8 (module tree of the `lib` target, `#[cfg]` pruning for the target and the shipped library's features, macro bodies included, proc-macro and build-time crates labelled and kept in the report), plus the network names; the baseline starts from `client-core/dm-spike/baseline/g-r8-baseline.txt` (moved to `ghost/scripts/gates/dm-vendored-clock-log.baseline` in S4a), with any unjustified entry failing the gate.

---

## 9. V-9: size of the DM stack inside `libghost_client_net.so`

**Method.** `scripts/v9-size-build.sh` builds `ghost-client-net` for arm64-v8a and x86_64 exactly as `scripts/build-native.sh` does (cargo-ndk 4.1.2, release, `strip = "symbols"`, path remapping), into this session's target directory, with portable libcrux. The baseline is the unpatched tree; the variants apply `size-probe/size-probe.patch`, whose probe crate calls what `ghost-client-dm` will call: a dehydrated-device account, outbound and inbound sessions, encryption and decryption, JSON pickles, and X-Wing key generation, encapsulation and decapsulation, either through libcrux-kem's enum API (`PublicKey`, `Ct`, `PrivateKey`) or through the `XWing` slice trait. One further build of the trait variant without stripping lists the linked symbols (`llvm-nm -C --defined-only`), and the stripped libraries are searched for constants unique to modules (`HPKE-v1`, `HPKEXXYYZZ`, `psk_id_hash`, `MATRIX_QR_CODE_LOGIN`, `OLM_KEYS`, `OLM_RATCHET`).

**Numbers (bytes).**

| Variant | arm64-v8a | Δ vs baseline | x86_64 | Δ vs baseline |
|---|---|---|---|---|
| baseline (`main` at `cc24c5c`) | 17 151 936 | — | 18 508 584 | — |
| probe linked, no DM feature (only its JNI exports; new lock) | 17 147 720 | −4 216 | 18 502 040 | −6 544 |
| vodozemac 0.11.0 only | 17 432 344 | +280 408 | 18 872 696 | +364 112 |
| libcrux-kem enum API only | 17 773 440 | +621 504 | 19 279 752 | +771 168 |
| vodozemac 0.11.0 + libcrux-kem enum API | 18 061 520 | +909 584 | 19 652 408 | **+1 143 824** |
| vodozemac 0.10.0 + libcrux-kem enum API | 18 040 416 | +888 480 | 19 600 112 | +1 091 528 |
| **vodozemac 0.11.0 + X-Wing slice trait** | **17 646 928** | **+494 992** | **19 138 488** | **+629 904** |
| same + vodozemac `precomputed-tables` | 17 675 744 | +523 808 | 19 152 104 | +643 520 |

- 0.11.0 against 0.10.0: +21 104 B (arm64-v8a), +52 296 B (x86_64).
- The enum API against the slice trait: +414 592 B (arm64-v8a), +513 920 B (x86_64): the enum dispatch links every KEM of the crate. The unstripped trait build contains no `libcrux_p256`, `libcrux_ecdh`, `mlkem512` or `mlkem1024` symbol.
- **`hpke` is dropped by the linker:** the unstripped trait build has no symbol of the `hpke` crate or of `vodozemac::hpke` (the two `hpke::` matches are `rustls::crypto::hpke` trait objects already in the baseline), and no stripped variant contains `HPKE-v1`, `HPKEXXYYZZ`, `psk_id_hash` or `MATRIX_QR_CODE_LOGIN`, while `OLM_KEYS` and `OLM_RATCHET` are present. Megolm, SAS, ECIES and `pk_encryption` are dropped as well (three serde visitor symbols of `megolm::SessionConfig` remain on x86_64).
- No libcrux SIMD symbol in either ABI (portable build). On x86_64, curve25519-dalek's AVX2 backend is linked (runtime-selected), which explains most of the x86_64 surplus.
- `precomputed-tables`: +28 816 B (arm64-v8a), +13 616 B (x86_64).
- Variation from lock and feature unification alone is about ±7 KB (the no-feature row).

**Conclusion.** With the slice-trait call path, the whole DM stack costs **+495 KB on arm64-v8a and +630 KB on x86_64**, inside the §2.7 budget of +1 MiB per ABI and above the earlier +0.2–0.5 MB estimate. With the enum API the x86_64 library would exceed the budget (+1.09 MiB). vodozemac 0.10.0 would save only 21–52 KB. `hpke` 0.14.1 is present in the source graph but not in the shipped binary, so it can leave the audit scope as §22.8.10 point 13 foresaw, provided the check is repeated at every bump. The precomputed tables cost 14–29 KB and speed up only key generation and Ed25519 signing inside vodozemac, which GHOST does not use for signing.

**Normative correction (S0-9).**
1. §2.3, direct dependencies: "`libcrux-kem =0.0.9` used **only through `libcrux_kem::XWing` and `libcrux_traits::kem::slice::Kem`** (the enum API links every KEM of the crate: +415 KB arm64-v8a, +514 KB x86_64, V-9), with `libcrux-traits =0.0.8`; the encapsulation-key check is an explicit `libcrux_ml_kem::mlkem768::validate_public_key` call (the trait does not check the ML-KEM half, V-6)". §22.8.2 rule 3 names that call.
2. §2.7 "Size": "Measured in S0′ (V-9): +494 992 B (arm64-v8a) and +629 904 B (x86_64) for vodozemac 0.11.0 and X-Wing through the slice trait, stripped; 0.10.0 would save 21–52 KB; the budget stays ≤ +1 MiB per ABI and `apk-size:` reports the library per ABI."
3. §2.9 audit scope and §16.3 `hpke` row: "`hpke` 0.14.1 is dropped by the linker (V-9: no symbol, no constant in the shipped library); it stays in the licence and advisory checks of the source graph and leaves the external audit scope while G-R7 repeats the V-9 symbol check at every vodozemac bump."
4. §16.1 G-R2: "`precomputed-tables` stays off (V-9: +14–29 KB for vodozemac-internal key generation and signing that GHOST does not use for identities)."
5. Q45: the default 0.11.0 stands; the size argument for 0.10.0 is 21–52 KB.

---

## 10. V-10: FailedDecryptLeavesStateTest

**Method.** `tests/v10_failed_decrypt.rs`, per pin. A responder session created from a first PreKey message (its sending ratchet is still inactive) receives a forged normal message: version 3, a random **contributory** ratchet key the session does not know, a random ciphertext and MAC. Three observations: (1) the misuse MC-29 (`decrypt_keeping_object`: decrypt on a live object and read its state back whatever the outcome); (2) value semantics (`decrypt`: new state only on success) followed by the sender's next valid message on the stored bytes; (3) the same forgery against an already active ratchet, and with an all-zero ratchet key. A last test persists the activated object and lets the peer decrypt the responder's next reply.

**Command.** `cargo test --release --test v10_failed_decrypt` → 6 passed (3 per pin).

**Results (both pins).**
- The failed decrypt returns `UNDECRYPTABLE`, and the live object's `sending_ratchet.type` has changed from `inactive` to `active` (the in-place activation of `vz:src/olm/session/double_ratchet.rs:168-191`, reached from `vz:src/olm/session/mod.rs:444-458`).
- With value semantics the stored pickle stays byte-identical and the next valid message decrypts on it.
- An active ratchet is not changed by the same failure, and an all-zero ratchet key fails before any change (`activate()` returns `None` first).
- A persisted activation does not break interoperation: the peer decrypts the responder's next reply. The defect is state drift: the stored state then depends on a forged, relay-injectable blob.

**Conclusion.** RX-1 and §7.9 point 2 are confirmed on both pins. The consequence is narrower than "diverges" suggests: it is not a message loss, it is a relay-controllable change of stored state, which breaks the byte-identical replay that the crash enumeration, the seeded worlds and T28's "no state change from an inbound blob" rely on.

**Normative correction (S0-10).** §7.9 point 2, append: "V-10 reproduced the activation on 0.11.0 and 0.10.0 (inactive ratchets only; an active ratchet and a non-contributory key leave the object unchanged). Persisting the activated object does not stop the peer from decrypting later replies; it is forbidden because it lets a forged blob change stored state (T28, byte-identical crash runs), which MC-29 detects." R-36: "impact: local state drift driven by forged blobs, not message loss".

---

## 11. V-12: vodozemac's own test suite

**Method.** `scripts/v12-vendor-tests.sh <version>` checks the `.crate` against its crates.io SHA-256, extracts it, and runs `cargo test --locked` with default features and with `--all-features` against the package's own `Cargo.lock`. Local attempt: `cargo test --locked --offline --no-run` in the extracted 0.11.0 package.

**Numbers.**
- The crates.io packages carry their unit tests in `src/` (169 `#[test]` functions in 0.11.0, 152 in 0.10.0), a `Cargo.lock`, and no `tests/` directory; `.cargo_vcs_info.json` names the tag commits `db1b34820f3102307284e762f335b3f72c735bf0` (0.11.0) and `bb39ec65357989f975e0d47f9fb35e0656180151` (0.10.0).
- The dev-dependencies (`olm-rs` 2.2.0 over `olm-sys` 1.3.2, `insta`, `proptest`, `codspeed-criterion-compat`, `assert_matches2`, `anyhow`) are not in the product lock and not in the local cache (the offline resolution stops at `assert_matches2`), and `olm-sys` builds libolm with CMake and a C++ compiler; this host has no `cmake`. **The suite was not run here** (§15).

**Conclusion.** The `vendor-tests` job must have network access to crates.io (or a vendored dev-dependency set), CMake and a C++ toolchain (the ghost-runner image has `cmake` and `build-essential`, `docs/ci-self-hosted.md` §2.1); the unit tests of the package are the only tests available without a git checkout.

**Normative correction (S0-11).** §15.2 item 1 and §16.2 `vendor-tests`: "runs `client-core/dm-spike/scripts/v12-vendor-tests.sh` (moved to `scripts/ci/` in S4b) for the pinned version: the checksum-verified crates.io package at the recorded tag commit, `cargo test --locked` with default features and with `--all-features`; needs crates.io access, CMake and a C++ compiler (`olm-sys`); its dev-dependency lock is checked by `cargo deny` in the job. If upstream integration tests exist outside the package, the job checks out the tag commit recorded in `.cargo_vcs_info.json` instead."

---

## 12. V-14: Ed25519, Kotlin/JDK against Rust

**Method.** `tests/v14_ed25519.rs` generates `vectors/ed25519-v14.txt` deterministically (the test fails if the committed file differs): 64 signing cases (seeds and messages of 0 … 96 bytes from SHA-256 counters; ed25519-dalek 2.2.0 public key and signature) and 53 verification cases built with curve25519-dalek 4.1.3, each with dalek's `verify_strict` and legacy `verify` results: a valid signature; a wrong message; S + L, S + 2L and a high bit in S; small-order public keys (the 8-torsion points), the identity key encoded non-canonically (y = p + 1) and with the sign bit; mixed-order public keys `a·B + T` with honest signatures under `a` (three messages per torsion point); mixed-order nonces `r·B + T`; small-order nonces `R = T` with `S = k·a`; a non-canonical identity nonce; a public key off the curve. `jvm/Ed25519Equivalence.java` replays the file on JDK 17 with BouncyCastle bcprov-jdk18on 1.85.2 through the exact behaviour of `:identity`'s `Ed25519KeyPair` (sign from a 32-byte seed; verify with the length checks and `IllegalArgumentException` → false).

**Commands.** `cargo test --release --test v14_ed25519`; `bash scripts/v14-ed25519-jvm.sh`.

**Numbers.**
- Signing: 64 of 64 public keys and signatures byte-identical.
- Verification: **20 of 53 identical to dalek `verify_strict`, 33 different.**

| Case class | BouncyCastle 1.85.2 | dalek `verify_strict` | dalek `verify` |
|---|---|---|---|
| valid, wrong message, S + L, S + 2L, S high bit, public key off the curve | same as strict | reject (valid: accept) | same |
| small-order public key (8 cases), identity key non-canonical or with the sign bit | reject | reject | accept for 7 of 10 |
| mixed-order public key with an honest signature (21 cases) | **accept all 21** | accept only the 3 with k·T = identity | same as strict |
| mixed-order nonce (7 cases) | **accept all** | reject | reject |
| small-order nonce with S = k·a (8 cases) | **accept all** | reject | accept only R = identity |
| identity nonce encoded non-canonically | reject | reject | reject |

**Conclusion.** Signatures agree. Verification does not: BouncyCastle 1.85.2 checks the **cofactored** equation `[8]SB = [8]R + [8]kA` and refuses small-order public keys; ed25519-dalek's `verify_strict` checks the cofactorless equation and refuses small-order public keys and nonces. Both are EUF-CMA secure and agree on every honestly generated signature, but an adversary who controls a key can build one signature that the JDK accepts and Rust refuses (a mixed-order key or nonce). R-37 has materialised; "strict verification in both" (§2.4, R-37) is not achievable with BouncyCastle's public API.

**Normative correction (S0-12).**
1. §2.4 "Ed25519 in Rust (X-21)", replace the last two sentences by: "Every artifact of X-21 (card v2, bundle v2, binding v3, revocation certificate v2) is signed **and verified only in Rust** (`verify_strict`); Kotlin never verifies them. BouncyCastle stays the only signer and verifier of the Phase 3 artifacts. Signatures are identical (Ed25519 is deterministic), verification is not: BouncyCastle 1.85.2 verifies cofactored and differs from `verify_strict` on mixed-order keys and small- or mixed-order nonces (V-14: 33 of 53 edge vectors)."
2. R-37: "materialised in S0′ (V-14); mitigation: one verifier per artifact type, never two; the vector files carry each case's `verify_strict` result, and the independent JDK implementation replays signatures in full and verification only as documented expectations per class (accept/reject of BouncyCastle recorded beside dalek's), so a BouncyCastle bump that changes a class fails the test."
3. §15.2 (Kotlin): "the Ed25519 vectors" becomes "the Ed25519 signing vectors and the verification-class expectations of V-14".

---

## 13. V-15: the skipped-key age bound (Q67)

**Method.** Neither pin has an API that drops receiver-chain message keys (`vz:src/olm/session/receiver_chain.rs`: the store is private; no public method removes a key). `src/prune.rs` edits the stored JSON pickle: it lists `receiving_chains.inner[].skipped_message_keys.inner[]` entries (`{key, index}`) with their chain's `ratchet_key`, removes the entries a predicate selects (keeping the order of the rest), and hands the result to `Session::from_pickle`. A key's first-seen day is state outside vodozemac: `added_keys(before, after)` returns the keys a call created, so the day of the call is recorded for them. `tests/v15_age_bound.rs`, per pin: (1) index 5 arrives on day 100 (keys 1–4 skipped) and index 10 on day 130 (keys 6–9); a sweep on day 152 with `FRESH + 2σ = 51 d` removes exactly the four day-100 keys; a pruned message then returns `DUPLICATE_OR_LOST`, a kept one decrypts, the chain continues; without the prune the old message still decrypts (the exception Q67 removes). (2) FIFO order survives: 20 skipped keys, the odd ones pruned, 27 more skipped (37 ≤ 40, order preserved), then 9 more (46 > 40): exactly the 6 oldest remaining keys are evicted. (3) An UpgradeTest drill: a pickle pruned under 0.10.0 loads under 0.11.0, the pruned key is gone, a kept key decrypts, and the sender continues under 0.11.0.

**Command.** `cargo test --release --test v15_age_bound` → 5 passed.

**Results.** All as expected on both pins; the edited layout (`receiving_chains.inner[].skipped_message_keys.inner[]` with `key` and `index`) is the same in 0.10.0 and 0.11.0 (V-4). Size of the first-seen state, if kept as a compact sidecar: per chain `ratchet_key(32) ‖ u8(n) ‖ n × (u64_be index ‖ u32_be day)`, at most `1 + 5 × (33 + 40 × 12) = 2 566 B`; the worst pickle plus the sidecar (36 685 + 2 566 = **39 251 B**) still fits `SESSION_STATE_MAX` with 26 285 B to spare.

**Conclusion.** The golden-pickle and UpgradeTest drills can cover the prune: the edit uses only the serialised layout, identical on both pins, and pruned pickles load across the pins. Q67's condition is met, so its default ("prune") applies. The prune needs one more native call: sessions that are never used again still hold old keys, so SWEEP must prune them.

**Normative correction (S0-13).**
1. §7.7 point 4: "**Skipped-key age bound (adopted; V-15).** Every call that stores a session state also stores, inside the same wrapped envelope, a first-seen sidecar `u8(chains) ‖ per chain: ratchet_key(32) ‖ u8(n) ‖ n × (u64_be chain_index ‖ u32_be first_seen_day)` for the keys that call added (day = the call's day). SWEEP calls `sessionPrune` on every live session; Rust removes from the JSON pickle (`receiving_chains.inner[].skipped_message_keys.inner[]`) every key with `today ≥ first_seen_day + FRESH + 2σ` (51 d) and its sidecar entries, keeping the order of the others. The P-7/T34 skipped-key exception is withdrawn; MC-30 joins the gate." (`decrypt`, `sessionInbound` and `encrypt` gain the `today` input.)
2. §2.6: add JNI function 20 `sessionPrune(h, contactId, sessionId, stateEnv, today) → state_env, pruned count` (`STATE_CORRUPT`); G-R6's list gains it.
3. §15.2 golden fixtures: each pin's directory holds pruned pickles with sidecars, and `UpgradeTest` loads the previous pin's pruned pickles and continues both ways (R-41's mitigation).
4. §0.2 P-7, §14.1 T34, §21.3 point 6, CS-8: the skipped-key exception is removed; §15.7 and §22.8.11: **97 mutants** (`dm mutants: 97 run, 97 detected`), §17.1 S10 "the 57 correctness and ephemeral mutants".

---

## 14. V-16: plan for the host/Android equivalence harness (RG-2, §15.9 item 7)

The spike cannot run it (no emulator or device on this host), so this is the plan S4b and S12 implement.

1. **Entry point.** `ghost-client-dm` feature `test-vectors` adds one JNI function `Java_org_ghost_crypto_bridge_DmNative_equivalence(byte[] input) → byte[] output`; it exists only in `ghost-dm-host` and in the emulator test library `libghost_dm_equivalence.so` (x86_64, packaged only in the `androidTest` APK). G-R6 checks the shipped `libghost_client_net.so` for its absence and both test libraries for its presence with `llvm-nm -D --defined-only` (V-5 showed the dynamic table survives stripping).
2. **Deterministic cases only** (no draw from `getrandom` on Android, where the custom backend is forbidden by G-R2): HKDF derivations and card v2 codec; the MSC3814 encoder and the identity keys of `Account::from_dehydrated_device`; X-Wing key generation from seeds and `encapsulate_derand`/decapsulation (the draft vectors plus 32 seeded cases); every seal mode with fixed salts, nonces and KEM randomness, and their openings; decryption of the golden transcripts from their stored pickles; normal-message encryption from a fixed **active** pickle (deterministic once the sending ratchet is active: the chain key fixes the message key, IV and MAC); pickle JSON after each of those steps; the prune of V-15 on a fixed pickle and sidecar; safety numbers; L0 and TLV codecs, including refusals (result codes are outputs too). PreKey creation (fresh base keys) and outbound session creation are excluded.
3. **Input and fixture.** `protocol/test-vectors/dm_equivalence.txt` lists the cases (`id ‖ kind ‖ hex input`); the `android` job runs them on `ghost-dm-host` and records `id ‖ SHA-256(output) ‖ hex output` as a job output fixture; `dm-emulator.yml` runs the same file through an instrumented test on the emulator's x86_64 library and compares byte for byte, printing the first differing case.
4. **Controls.** A self-test case whose input differs between the two runs by one byte must be reported as different (the comparator is not vacuous); the report line `dm-equivalence: N cases, N identical, control detected` is required by `dm-report-check.sh`; a job that cannot boot the emulator reports "not run" (§15.9).
5. **Same build inputs.** Both libraries come from one commit, one `Cargo.lock`, Rust 1.98.1, the portable libcrux cfgs (G-R3 on both builds) and the same feature set plus `test-vectors`; the fixture header records the commit and both build-script cfg lists, and the comparison refuses fixtures from another commit.
6. **Not covered, declared:** arm64 execution (the emulator image is x86_64; arm64 is exercised by the release smoke test on the physical devices, §15.10), CPU-dependent backends (curve25519-dalek selects its x86_64 backend at run time; outputs are equal by definition but the code differs), and anything randomised.
7. **Spike assets reused:** the JNI shape and `catch_unwind` of `src/jni_host.rs`, the JVM loader of `jvm/org/ghost/dmspike/DmHostProbe.java`, and the export listing of `scripts/v5-host-load.sh`.

**Normative correction (S0-14).** §15.9 item 7: replace the list of inputs by "the deterministic case set of `protocol/test-vectors/dm_equivalence.txt` (evidence V-16: derivations, card, MSC3814 encoder, X-Wing from seeds and fixed encapsulation randomness, every seal mode with fixed salts and nonces, golden-transcript decryption, normal-message encryption from a fixed active pickle, the prune, safety numbers, L0/TLV codecs with refusals; no PreKey creation)", and add the control case, the fixture header check and the report line of V-16 points 4 and 5.

---

## 15. Not done on this host, and why

| Item | Why not here | Where it is closed |
|---|---|---|
| V-5 on Linux (ubuntu-24.04, JDK 17) | This host has no Linux Rust toolchain outside the `ghost-runner` WSL distribution, which serves the CI runners and was off limits for this slice; building a container image would have meant downloading toolchain images, which this session did not do | the first `android` job run executes `scripts/v5-host-load.sh` (S0-5 point 3) |
| X-Wing draft-10 vectors | not in the local registry; fetching the IETF text was not done in this session. The draft-06 vectors came from the local `x-wing` 0.1.0 crate | S4a vector import (both drafts, with the text's SHA-256 recorded) |
| Byte comparison of `vectors/xwing-draft06.json` with the draft-06 Appendix text | same | S4a |
| V-12 run | dev-dependencies of vodozemac not cached and `cmake` absent (`olm-sys`) | `vendor-tests` job on the runner image (S0-11) |
| Low-end phone timings (V-6) | no device or emulator attached | §15.10 step 9 |
| V-16 run | no emulator on this host | S12 (`dm-emulator.yml`) |
| Timings without background load | the four CI runners kept the host at 99–100 % CPU during the first session; the 2026-09-19 re-run on an idle host is recorded beside them in §6.4 | the device checklist; the loaded host numbers are the upper bounds |
| EM-1, KC3b, `WrapBindingTest`, PQ6 (V-17), the CI plan on private 2-CPU runners (§22.8.9 point 4) | not assigned to this slice | S4b, S0′ owner and CI work |
| The G-R8 and G-R3 gates as `ghost/scripts/gates/*.sh` with negative fixtures and `self-test.sh` entries | the spike delivers the scanner, the detector, the baseline and the fixtures' content; turning them into gates changes the gate scripts and the product lock, which this slice leaves to S0′'s gate work | S0′ gate slice |

---

## Appendix V. Verification run, 2026-09-19

(An appendix, not §16: inside this document "§16.1" always means `faza9-dm.md` §16.1.)

The first session was interrupted before its results were checked, so every check above was re-run from scratch on the same host and each number in this document was compared with what the run produced. The host was idle this time (the CI runners were not building), which is the only reason any number moved.

**What was run.** `cargo test --release --locked -- --nocapture` (44 tests over 9 integration targets, all passed); `cargo test --release --locked --features v2-config --test v3_v2_margin`; `cargo fmt --check`; `cargo clippy --locked --all-targets -- -D warnings` with no features, with `jni-host` and with `v2-config`; `scripts/v5-host-load.sh`; `scripts/v14-ed25519-jvm.sh`; `scripts/libcrux-portable-detector.sh` over the four-step sequence of §6.3 in a scratch crate; `scripts/v12-vendor-tests.sh 0.11.0`; and, with `size-probe/size-probe.patch` applied, `scripts/v8-g-r8-baseline.sh`, `cargo deny --offline check`, all eight `scripts/v9-size-build.sh` variants (seven patched plus the unpatched baseline, two ABIs each) and one extra unstripped arm64-v8a build for the symbol check of §9. The three gate suites (`scripts/gates/run-all.sh`, `GHOST_SELFTEST_OPS=1 scripts/gates/self-test.sh`, `scripts/gates/rust-gates.sh`) were green before and after, and the worktree was left with the probe patch reverted and `ghost/Cargo.lock` restored.

**Reproduced exactly.**

| Check | Evidence |
|---|---|
| V-1 | 9 tests; the JVM run of V-5 prints `OI = d80580ec…0603` for root entropy `000102…1f`, the value §3.1 is to pin |
| V-2 | 8 tests, both pins |
| V-3 | every cell of the §3 table (179/173, 73/67, 181/175, 74/68; intro 1 606, pair 128; capacities 2 220 / 14 508 / 63 660; slack 60/60/58; 3 120 outputs per pin) and the V2 margin (PreKey 205, normal 98, intro 1 630, margin 34) |
| V-4 | widened bound 36 685 B = `analytic_bound`, margin 28 851 B (44.0 %), both pins; 0.10.0 pickle loads byte-identically in 0.11.0. The *driven* length is data-dependent, see §4 |
| V-5 | `ghost_dm_spike.dll` 1 479 680 B with exactly 3 JNI exports; `olmRoundTrip` 0, `xwingRoundTrip` 0 with a 1 216-byte key and equal secrets, `panicProbe` 0xff with the JVM alive and the default hook printing `kem.rs:246` to stderr; JDK 17.0.20.1. On Android, both ABIs export `probeOlm`, `probeKem` and `probeDirect` **beside exactly 21 pre-existing `Java_org_ghost` exports**, with no libcrux SIMD symbol |
| V-6 | 8 tests (3 draft-06 vectors, 256 differential pairs, 6 low-order u-coordinates, both panics, the slice-trait path); the §6.3 detector sequence FAIL → FAIL → portable → portable; the added package names are exactly the 11 + 15 of G-R1 on both triples; 0.10.0 drops `hpke`, `serdect`, adds `opaque-debug`; every version set of §6.2; no `cc`, `cmake`, `bindgen`, `clang-sys`, `crabgrind` or `libloading` in either triple's normal+build graph and no `links` key; `cargo deny --offline check` = **licenses ok, bans ok, sources ok, advisories FAILED** on `RUSTSEC-2026-0173` alone, through `hax-lib-macros`; no copyleft licence anywhere in the DM stack (every added package is Apache-2.0, `MIT OR Apache-2.0`, `Apache-2.0 OR MIT` or the legacy `MIT/Apache-2.0`, and the three new dalek majors are BSD-3-Clause — all on `ghost/deny.toml`'s allowlist) |
| V-7 | all four rows of the §7 table, worst-of-three relay variant by relay variant: 2 303 (198) / 1 470 (187) / 0 / 0 / 0 and 2.1 min; 157 (46) / 75 (23) / 0 / **57 (20)** / 0 and 10.6 min; 2 238 (197) / 1 432 (184) / 0 / 0 / 0 and 2.3 min; 0 everywhere and 0.4 min. The model matched vodozemac in all 72 × 200 worlds |
| V-8 | 39 sites (31 linked, 8 build-time), 137 `cargo:` lines in 17 build scripts, 100 packages / 74 linked / 10 proc-macros / 16 build-time, the two `include!` notes and no unparsed file; the committed `baseline/g-r8-baseline.txt` matches the fresh scan key for key (176 lines); 23 `log::` in `jni`, 2 in `memchr`, 4 in `serde_core`, 1 in `rand`, 1 in `libc`; **0 sites in vodozemac, hpke, matrix-pickle and every libcrux crate**; `log` reached only through `jni`, `tracing` not in the DM graph |
| V-9 | **every byte of the §9 table**, all eight variants × two ABIs, including the baseline 17 151 936 / 18 508 584 and the headline 17 646 928 / 19 138 488 (+494 992 / +629 904), and with them every derived figure: +21 104 / +52 296 for 0.11.0 over 0.10.0, +414 592 / +513 920 for the enum API over the slice trait, +28 816 / +13 616 for `precomputed-tables`, −4 216 / −6 544 for the lock-and-features row. No stripped variant contains `HPKE-v1`, `HPKEXXYYZZ`, `psk_id_hash` or `MATRIX_QR_CODE_LOGIN`, while `OLM_KEYS` and `OLM_RATCHET` appear exactly in the variants that link vodozemac. An **unstripped** arm64-v8a build of the slice-trait variant (`--config profile.release.strip=false`, 55 013 defined symbols) confirms the linker claims directly: no `libcrux_p256`, `libcrux_ecdh`, `mlkem512` or `mlkem1024` symbol, `mlkem768` present, no symbol of the `hpke` crate or of `vodozemac::hpke` (the only match is `rustls::crypto::hpke::HpkeSealer`, already in the baseline), none of `vodozemac::megolm`, `::sas`, `::ecies` or `pk_encryption`, and no `simd128`/`simd256` symbol |
| V-10 | 6 tests, both pins |
| V-12 | both `.crate` checksums match the pinned values to the byte, 169 and 152 `#[test]` functions, no `tests/` directory, the two tag commits, `LICENSE` only for vodozemac and no licence file at all in the libcrux crates. The script itself exits 2 on this host (`cmake` absent), as §15 declares |
| V-14 | 64 of 64 signatures identical; 53 verification cases, **20 identical to `verify_strict`, 33 different**, class by class: BouncyCastle accepts all 21 mixed-order keys where strict accepts 3, all 7 mixed-order nonces and all 8 small-order nonces, and legacy `verify` accepts 7 of the 10 small-order-key cases. `scripts/v14-ed25519-jvm.sh` exits 1 by design: its comparator treats any difference from `verify_strict` as a failure, and these 33 differences are the finding of V-14, not a defect of the run |
| V-15 | 5 tests, both pins |
| source citations | `vz:src/olm/session/mod.rs:55` (`MAX_RECEIVING_CHAINS = 5`), `receiver_chain.rs:31,50` (`MAX_MESSAGE_GAP = 2000`, `MAX_MESSAGE_KEYS = 40`), `double_ratchet.rs` `advance` (in-place activation), `account/mod.rs` (`#[doc(hidden)] from_decrypted_dehydrated_device`, "public for fuzzing"; the fallback key kept on inbound creation), `kem:246` and `kem:574` (the two slice-index panics), `libcrux-ml-kem-0.0.10/src/lib.rs` `impl_kem_trait` (`encaps` performs no `validate_public_key`). None of `SessionCreationError`, `DecryptionError`, `EncryptionError` is `#[non_exhaustive]` on either pin |

**Corrected in this document by the verification run.**

1. §4: the *driven* JSON lengths (previously "29 880 B" and "29 848 B") are not reproducible — the pickle holds random key bytes whose decimal spellings vary in length. Four runs spanned 29 818–29 879 B (0.11.0) and 29 719–29 831 B (0.10.0). The widened bound of 36 685 B, which is the number `SESSION_STATE_MAX` rests on, is deterministic and unchanged.
2. §6.4: the timing table now carries both the loaded and the idle measurement. Nothing in §0.1, §9.2 or the S0-6 correction changes: those quote the loaded numbers, which remain the upper bounds.
3. §6.2: `chacha20poly1305 0.11.0` was listed both as an added name and as a new version of an existing name. It is a new name; the unpatched graph holds no `chacha20poly1305`. The "new versions of existing names" list is nine entries, identical on both triples.
4. §6.2: `curve25519-dalek-derive 0.1.1` was recorded as added on x86_64. It is already in the unpatched x86_64 graph (curve25519-dalek 4.1.3's SIMD backend); the DM stack adds it on neither triple.
5. §13: the worst pickle plus the first-seen sidecar is 36 685 + 2 566 = **39 251 B**, not 39 255 B. The conclusion (it fits `SESSION_STATE_MAX`) is unchanged.
6. Header: the host row now records the measured machine (95.4 GiB RAM, 24 threads, Windows build 10.0.26200) instead of a rounded figure.

No spike test or script needed a fix to build or run: `cargo fmt --check` and all three `cargo clippy --all-targets -- -D warnings` configurations were already clean, and every test and script behaved as this document describes.
