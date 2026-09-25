# GHOST Phase 10, slice S0: OpenMLS evidence (checks V10-1 … V10-14)

| Field | Value |
|---|---|
| Design | `docs/design/faza10-forum.md` (round 10c, `d9ff300`), §14 row S0 with checks V10-1 … V10-14, and every other place those checks are named (§3.3, §3.4, §3.6, §3.8, §5.4, §5.6, §5.7, §6.8, §10.1, §12.1, §12.2, §13.1, §13.3, §15, §16, §17, §19.4, §19.5, §19.10, §19.11, §19.18, §19.23, Appendix C E-14 … E-25) |
| Scope of this document | all fourteen checks. Run here: V10-1 … V10-9, V10-11 … V10-14 in full; V10-10 on the host and on an x86_64 Android emulator, **not on a low-end device** (§15) |
| Date | 2026-09-25 |
| Branch | `p10-s0` (worktree of `D:/Forum`), base `d9ff300` |
| Toolchain | Rust 1.98.1 (`ghost/rust-toolchain.toml`), cargo-ndk 4.1.2, Android NDK 30.0.16248370, cargo-deny 0.20.2, cargo-audit 0.22.2, `gh` (GitHub API) |
| Host | Windows 11 Pro 10.0.26200, Intel Core Ultra 9 275HX (24 cores), 95.4 GiB RAM. **The host was at 100 % CPU during every timing** (other builds share it; sampled before and after the V10-10 runs): every time in this document is a loaded-host figure and bounds nothing |
| Pins measured | `openmls` 0.9.0 (`.crate` SHA-256 `b6b08d90…a8c8`, built from `3a3e35de3feeca8f6605143c464d5452ae584d43` = tag `openmls-v0.9.0`, `.cargo_vcs_info.json`), `openmls_traits` 0.6.0 (`ac13edad…831c`), `openmls_libcrux_crypto` 0.4.0 (`41e6367f…4855`), `openmls_memory_storage` 0.6.0 (`ce927945…5364`), `openmls_serialization_helpers` 0.1.0 (`0e2cf219…84c0`), `hpke-rs` / `-crypto` / `-libcrux` 0.7.0 (`812de62a…b7b1`, `d2c461da…0e24`, `4c1ace95…2613`), `tls_codec` 0.5.0 (`18cc9828…67c8`); every hash equals the `checksum` the resolved lock records |
| Code | `ghost/client-core/mls-spike` (virtual workspace: `ghost-mls-spike`, `ghost-mls-spike-kat`) and the temporary patch `ghost/client-core/mls-spike/size-probe/size-probe.patch` |
| Status | Evidence for the lead. **This document does not edit `faza10-forum.md`; every CORRECTS or INCONCLUSIVE check ends with the exact normative correction (S0-n) to fold in after review.** |

**How to read.** §0 summarises the verdicts, the values to freeze and the corrections. §1 … §14 are one check each: the question, the method, the commands, the numbers, the verdict and, where the verdict is not a plain CONFIRMS, the correction with its consequences, effort and owner questions. §15 lists what could not run on this host and why. Appendix A is the re-read of the SRLabs report the design asked S0 for (E-25); Appendix B is the verification re-run. Paths are relative to the repository root. `om:` cites `openmls-0.9.0` in the local cargo registry, `ot:` `openmls_traits-0.6.0`. "Blank" means the tree right after one batch add by the owner (only the owner's direct path is set, every other parent blank); "populated" means every parent node set (every member self-updated once).

---

## 0. Summary

### 0.1 Verdict per check

| Check | Question (short) | Verdict | Correction |
|---|---|---|---|
| V10-1 | graph, licences, cargo-deny, MPL | **CORRECTS** — OpenMLS 0.9.0 does not resolve into the ghost lock at all (a `links = "sqlite3"` conflict through its *optional* `openmls_sqlite_storage`); with a stub it adds exactly 22 names, no new version, no copyleft, cargo-deny green | S0-1 |
| V10-2 | advisories at the pins | **CORRECTS** — nothing open at the pins, but §3.7's list is incomplete and OpenMLS's advisories are **not in RustSec**, so cargo-deny/cargo-audit cannot see them | S0-2 |
| V10-3 | size in `libghost_client_net.so` | **CONFIRMS** the budget: +2 486 384 B (arm64-v8a), +2 919 168 B (x86_64), ≤ +3 MiB; numbers replace the probe's | S0-3 |
| V10-4 | commit/Welcome sizes at the caps, composite worst cases | **CORRECTS** — with a GHOST-shaped KeyPackage every single-proposal commit fits both floors; with a KeyPackage at §6.2.4's 1 024 B bound an Add exceeds C(4096) from 27 members, and leaf inflation (by joiners or by members' own self-updates) makes 100-member Welcomes exceed 64 KiB | S0-4, S0-5 |
| V10-5 | adapter cost | **CORRECTS** — 53 storage methods, not 72; OpenMLS rewrites all retained past epochs on every post (up to 1.19 MB at 32 and 3.39 MB at 100 members per post); fix measured | S0-6 |
| V10-6 | determinism | **CONFIRMS** the process-global stream (two processes byte-identical) with two stated preconditions | S0-7 |
| V10-7 | portable libcrux | **CONFIRMS** §19.23 (`libcrux-aes` stale cfg reproduced; portable builds verified from build outputs and symbols); S0 decides: extract the script | S0-8 |
| V10-8 | bootstrap in the Welcome's GroupInfo | **CONFIRMS** — reaches it, authenticated by the GroupInfo signature; the fallback is not needed | S0-9 |
| V10-9 | 0x004D/0x004F with libcrux (Q2 evidence) | **CONFIRMS** D3 with corrected numbers (both work end to end; 28.8–48.3 KB commits at 20–32 members) | S0-10 |
| V10-10 | host timings; low-end device | **INCONCLUSIVE** for devices (none available); host and x86_64-emulator figures recorded | S0-11 |
| V10-11 | OpenMLS's wall-clock sites | **CORRECTS** — the world range holds, but a lifetime refusal masks other defects of the same commit (measured), so CO-2's "lifetime-pending, ranked as valid" is unsound; OpenMLS never checks the lifetime span | S0-12 |
| V10-12 | passive-client replay through GhostKv | **CORRECTS** (in the design's favour) — every vector of the provider's suites replays (43 vectors, 252/252 epochs, 1 861 reload-oracle checks); the subset is set by suites, not by the clock | S0-13 |
| V10-13 | `refresh_epoch`, `GhostKpBind`, AAD round trips | **CONFIRMS** | — |
| V10-14 | nightly occupancy | **CORRECTS** — measured 1 111–2 720 runner-minutes per night, spans 5–25 h, queue waits up to 23 h, while the DM gates fail within two minutes; adding three nightly channel gates does not fit | S0-14 |

### 0.2 Values to freeze

| Constant | Value | Evidence |
|---|---|---|
| GHOST KeyPackage (MlsMessage, canonical form) | **395 B**, every time (lifetime, `GhostLeaf` 41 B, `GhostKpBind` 38 B, capabilities of §3.5) | V10-4, V10-13 |
| Largest single-proposal commit at the small cap (32, blank tree, canonical KeyPackage) | 3 786 B (restore swap), margin 242 B to C(4096) = 4 028; Add 31→32: 3 745 B | V10-4 |
| Largest single-proposal commit at the large cap (100, blank) | 10 102 B with a 1 024 B KeyPackage; 9 473 B canonical; margin ≥ 6 214 B to C(16384) | V10-4 |
| Welcome for one joiner | 8.8–12.1 KB at 32 (16 KiB bucket), 25.9–34.7 KB at 100 (64 KiB bucket) | V10-4 |
| Library delta (stripped) | +2 486 384 B arm64-v8a, +2 919 168 B x86_64; PQ feature +16 896 / +30 640 B more | V10-3 |
| `MessageSecrets` row per retained past epoch | 18.6 KB (32 members), 52.9 KB (100) | V10-5 |
| StorageProvider methods in the P0 feature set | 53 (41 group-scoped, 12 global) + `version()` | V10-5 |
| Nightly occupancy (4 self-hosted runners) | 1 111–2 720 runner-min per night (8 nights, 2026-09-17 … 24) | V10-14 |

### 0.3 Normative corrections (to be merged by the lead after review)

| # | Check | Sections | Correction (short) |
|---|---|---|---|
| S0-1 | V10-1 | §3.2, §13.1 G-M1/G-M2, §13.3, ADR-40, F-5, new Q40 | a manifest-only `[patch.crates-io]` stub for `openmls_sqlite_storage` (the lock does not resolve otherwise); the G-M1 list confirmed at 22 names; notice texts from outside the `.crate`s |
| S0-2 | V10-2 | §3.1, §3.7, §13.1 G-M1, §13.2 | the full advisory list; a weekly GitHub-advisory check for OpenMLS, hpke-rs and libcrux, which RustSec does not cover for OpenMLS |
| S0-3 | V10-3 | §3.8, R-4, E-15 | measured size frozen; the unused KEM code and the dropped memory provider recorded |
| S0-4 | V10-4 | §6.2.4, §5.7, D15, R-19, E-14, E-21 | a canonical KeyPackage (exact capabilities and extensions, 395 B golden) replaces "≤ 1 024 bytes"; §5.7's table replaced by the measured one |
| S0-5 | V10-4 | CO-2, §5.4, §12.9 (new mutant), L8-C11 | every leaf a commit installs has the canonical capabilities and exactly `GhostLeaf`: four inflated self-updates otherwise lock joins out of a 100-member channel |
| S0-6 | V10-5 | §3.4, §3.5, §8.3, §6.3.6, R-3, Q18, E-9 | 53 methods; per-epoch rows for past epochs in `GhostKv` (a second recorded serde-layout deviation); `max_past_epochs` 64 → 16; Q18 re-asked with the numbers |
| S0-7 | V10-6 | §3.6, §12.1, §19.10 | preconditions of byte-identical runs: one rayon worker, the `added_at` day rewrite, one getrandom major with the `__getrandom_v03_custom` symbol |
| S0-8 | V10-7 | §13.1 G-M9, §19.23 | `ghost/scripts/gates/libcrux-portable.sh` extracted, generic over the four packages, used by every workflow |
| S0-9 | V10-8 | §5.2, §5.4, §5.6, §10.2 fn 5 and 9, PC-17 | the bootstrap travels only in the GroupInfo; `K_boot` and `boot_flag` withdrawn; `create_group_info(false)` on every commit; the V10-8 test kept as a regression test |
| S0-10 | V10-9 | D3, §4.1, §4.2, Q2 | measured PQ sizes and behaviour replace the research figures |
| S0-11 | V10-10 | §12.11, §12.12, R-3 | host and emulator figures recorded; the device step runs the S2 successor of `device_probe` |
| S0-12 | V10-11 | CO-2, §3.5, §3.6, §6.2.4, §19.4, L8-C20, EM-3, MM-27 | lifetime-pending candidates are never "ranked as valid"; GHOST checks lifetime structure deterministically in CO-2 (A); a pending candidate expires by the member's trusted day |
| S0-13 | V10-12 | §12.2, §13.2, §13.3, §15 item 7, E-24 | the replayed subset is defined by the provider's suites (43 of 148 vectors, 252 epochs); `mls-vendor-tests` enables `all-ciphersuites`; the vectors' licence recorded |
| S0-14 | V10-14 | §12 (lessons), §13.2, §14, R-7, Q20 | the channel gates rotate weekly and run on dispatch; fuzzing weekly until capacity exists; Q20 re-asked with the measurement |

**Effort** (F9 pace, the unit of §14): S0-1 0.25 d, S0-2 0.25 d, S0-5 0.5 d, S0-6 1 d, S0-8 0.5 d, S0-12 0.5 d, S0-4/S0-9/S0-13 ≈ 0 net (S0-9 removes code). **About +3 working days** over §14's 34.5 (S2 +2, S5 +0.5, S1/CI +0.5).

**Owner questions raised or re-asked.** **Q40 (new)**: accept the stub patch of S0-1 (default yes). **Q18 (re-asked)** with the V10-5 numbers (default: value semantics kept, per-epoch rows, cap 16). **Q20 (re-asked)** with the V10-14 numbers (default: channel gates weekly by rotation plus dispatch). Q2 and Q3 keep their defaults; their evidence changes (S0-10, S0-4).

### 0.4 The spike

`ghost/client-core/mls-spike` is **not a member of the ghost workspace**: it is a virtual workspace with its own `Cargo.lock` (the `dm-spike` precedent), so the product lock, `rust-dependency-allowlist.txt`, the crypto pins and the ghost `cargo deny` are untouched. Its `core/src` passes `anti-placeholder.sh`, `no-logging.sh` and `dm-jni-surface.sh` (run on the tree with the spike present); `cargo fmt --check` and `cargo clippy --all-targets -D warnings` are clean for `ghost-mls-spike` (default, `pq`, `det`) and `ghost-mls-spike-kat`. The README (`ghost/client-core/mls-spike/README.md`) gives every command. **Fate:** deleted when `ghost-client-mls` and `ghost-client-mls-kat` land in S2; nothing in it is a production source.

---

## 1. V10-1: dependency graph, licences, cargo-deny, MPL

**Question.** Which packages does OpenMLS 0.9.0 with the libcrux provider add to the shipped graph of `libghost_client_net.so` on both Android triples, under which licences, and do `cargo deny` and the licence rules of ADR-37 stay green?

**Method.** The patch `size-probe/size-probe.patch` adds a temporary crate `ghost-mls-probe` (the spike's `GhostKv`, provider, extensions and harness compiled by `#[path]`, so it makes every call `ghost-client-mls` will make) to the ghost workspace and to `ghost-client-net` behind the features `mls-probe` and `mls-probe-pq`. The lock was resolved `--offline` against the existing `ghost/Cargo.lock`. Then `cargo tree --offline -p ghost-client-net -e normal --target {aarch64,x86_64}-linux-android` with and without the features, `-e normal,no-proc-macro` for what is linked, licences read from each package's `Cargo.toml` in the registry, a scan of every added crate's sources for GNU licence text, SPDX identifiers and "Signal Messenger" copyrights, and `cargo deny --offline check` with `ghost/deny.toml`.

**Result 1 — the lock does not resolve.** With `openmls = "=0.9.0"` in the workspace, `cargo metadata --offline` fails:

```
error: failed to select a version for `libsqlite3-sys`.
    ... required by package `rusqlite v0.37.0`
    ... which satisfies dependency `rusqlite = "^0.37"` of package `openmls_sqlite_storage v0.3.0`
    ... which satisfies dependency `openmls_sqlite_storage = "^0.3.0"` of package `openmls v0.9.0`
package `libsqlite3-sys` links to the native library `sqlite3`, but it conflicts with a previous package which links to `sqlite3` as well:
package `libsqlite3-sys v0.37.0`
    ... which satisfies dependency `libsqlite3-sys = "^0.37.0"` of package `ghost-client-net v0.1.0`
```

`openmls_sqlite_storage` is an **optional** dependency of `openmls` (feature `sqlite-provider`, forbidden by §3.2), but Cargo resolves the lock for every feature, and `links` values must be unique in the whole resolve. The ghost lock has `rusqlite 0.39.0` → `libsqlite3-sys 0.37.0` (Arti's directory cache); `openmls_sqlite_storage 0.3.0` requires `rusqlite ^0.37` → `libsqlite3-sys ^0.35`. There is no newer `openmls_sqlite_storage` (crates.io: 0.3.0 of 2026-08-25 is the newest; its `rusqlite` requirement is `^0.37`), and upstream `main` (`0cf0b0d`, 2026-09-24) still pins `rusqlite = "0.37"`. The research probes never met this because they built in their own workspaces without Arti.

**Workaround measured.** A stand-in crate with the same name and version and no dependencies (`openmls_sqlite_storage` 0.3.0, empty `lib.rs`, the four feature names `openmls` forwards to it declared empty), wired in by `[patch.crates-io]`, lets the lock resolve: +40 lock entries, of which 22 are linked (below); the other 18 are optional graph members that nothing enables (`openmls_rust_crypto`, `openmls_basic_credential`, `openmls_test`, `hpke-rs-rust-crypto`, `k256`, `ml-dsa`, `aes`, `aes-gcm`, `ctr`, `ghash`, `polyval`, `universal-hash`, `chacha20 0.9.1`, `chacha20poly1305 0.10.1`, `poly1305 0.8.0`, `aead 0.5.2`, `opaque-debug`, the stub). Because the sqlite feature is forbidden, the stub is never compiled into any graph.

**Result 2 — the graph (with the stub).**

| | arm64-v8a | x86_64 |
|---|---|---|
| package names, baseline → with the MLS stack | 417 → 439 | 418 → 440 |
| name+version pairs | 461 → 483 | 462 → 484 |
| names added (identical on both triples) | 22 | 22 |
| new versions of names already present | 0 | 0 |
| added by `mls-probe-pq` over `mls-probe` | 0 | 0 |

The 22 names, with versions and declared licences: `openmls` 0.9.0, `openmls_traits` 0.6.0, `openmls_libcrux_crypto` 0.4.0, `openmls_memory_storage` 0.6.0, `openmls_serialization_helpers` 0.1.0 (MIT); `hpke-rs`, `hpke-rs-crypto`, `hpke-rs-libcrux` 0.7.0 (**MPL-2.0**); `libcrux-aead` 0.0.9, `libcrux-aes` 0.0.9, `libcrux-chacha20poly1305` 0.0.9, `libcrux-ed25519` 0.0.9, `libcrux-hkdf` 0.0.8, `libcrux-hmac` 0.0.8, `libcrux-hmac-drbg` 0.0.1, `libcrux-poly1305` 0.0.6 (Apache-2.0); `rayon` 1.12.0, `rayon-core` 1.13.0, `crossbeam-deque` 0.8.8, `crossbeam-epoch` 0.9.21 (MIT OR Apache-2.0); `tls_codec` 0.5.0, `tls_codec_derive` 0.5.0 (Apache-2.0 OR MIT). `tls_codec_derive` and `openmls_serialization_helpers` are proc-macro/build-time only: the linked set (`-e normal,no-proc-macro`) is the other 20. `libcrux-sha2`, `libcrux-kem`, `libcrux-ml-kem`, `crossbeam-utils` and `either` are already in the baseline graph (the DM stack and Arti), so §13.1's G-M1 list ("… `crossbeam-utils`, `either`, … minus names already present") is exact once those are removed.

**Licence facts.** No added source file contains GNU licence text, a GNU SPDX identifier, an MPL header or a "Signal Messenger" copyright (scan of all 566 `.rs` files of the 22 crates). **None of the OpenMLS, hpke-rs or libcrux `.crate` archives ships a LICENSE file** (only `rayon*`, `crossbeam*`, `tls_codec*` do): the notices generator must take the MIT text with the upstream copyright line "Copyright (c) 2020 OpenMLS Authors" (repository `LICENSE` at `3a3e35de`, read) and the MPL-2.0 and Apache-2.0 texts from the SPDX snapshot, as Phase 9 did for libcrux.

**cargo-deny** on the patched workspace (`all-features = true` as `deny.toml` sets it): **advisories ok, bans ok, licenses ok, sources ok** with the cached database of 2026-09-22 and with a fresh one (V10-2). MPL-2.0 is on the allow list; the path source of the stub does not trip `sources`.

**Verdict: CORRECTS.** The design's graph and licence claims hold, but the stack cannot enter the workspace as §3.2 writes it.

**Normative correction (S0-1).**
1. §3.2, after the pins block, add: "**Lock resolution (V10-1).** `openmls` 0.9.0 declares the optional dependency `openmls_sqlite_storage` 0.3.0 → `rusqlite ^0.37` → `libsqlite3-sys ^0.35` (`links = "sqlite3"`), which conflicts with `ghost-client-net`'s `libsqlite3-sys 0.37.0`; Cargo resolves optional dependencies into the lock, so the workspace does not resolve at all. `ghost/Cargo.toml` therefore carries `[patch.crates-io] openmls_sqlite_storage = { path = "third_party/openmls-sqlite-storage-stub" }`: an empty crate of the same name and version with the feature names `openmls` forwards (`draft-ietf-mls-pq-ciphersuites`, `extensions-draft`, `virtual-clients-draft`, `test-utils`) and a README naming this correction. It is a manifest-level stand-in for a forbidden feature, not a modification of OpenMLS's code, and it is removed when upstream relaxes the requirement (F-5)."
2. §13.1 G-M2 gains: "`cargo tree -i openmls_sqlite_storage` over every shipped, host and test graph prints nothing (the stub is never compiled); the stub has no dependency and no source beyond an empty `lib.rs` (checked by hash)." G-M1 names the 22 packages of V10-1 exactly.
3. §13.3 gains the row "`openmls_sqlite_storage` stub 0.3.0 | none (never compiled) | MIT (GHOST's own stand-in) | ADR-40, G-M2". The notices row (G-L1) states that the OpenMLS, hpke-rs and libcrux crates ship no licence file and that their texts come from the upstream repository at the pinned commit (OpenMLS's copyright line) and the SPDX snapshot.
4. F-5 gains: "relax `openmls_sqlite_storage`'s `rusqlite` requirement (or drop the optional dependency from `openmls`)".
5. ADR-40 records the patch; **Q40 (new)**: "Accept a manifest-only `[patch.crates-io]` stub for OpenMLS's optional SQLite provider, which GHOST never enables, so that OpenMLS resolves next to Arti's SQLite? (Alternatives: wait for upstream; or pin Arti's `rusqlite` back to 0.37, which Arti 0.46 does not allow.)" — default **yes**.

*Effort:* 0.25 day in S2. *Consequences:* none on formats or protocol.

---

## 2. V10-2: advisories at the pins

**Question.** Is any advisory open against the pinned OpenMLS stack, and does the project's advisory tooling see them?

**Method.** (1) `cargo audit` 0.22.2 with a fresh clone of `rustsec/advisory-db` (commit `593df8c1`, 2026-09-24 16:38 +0200) into the scratchpad (`--db … --no-fetch`), on the patched `ghost/Cargo.lock` and on the unpatched one. (2) `cargo deny check advisories` with a copy of `ghost/deny.toml` whose `db-path` pointed at a fresh scratch database (the same commit). (3) Every RustSec entry for a crate of the stack, read. (4) GitHub repository advisories of `openmls/openmls`, `cryspen/hpke-rs` and `cryspen/libcrux` through the API.

**Numbers.**
- `cargo audit`, patched vs unpatched lock: **identical findings** — `rsa` 0.9.10 and 0.10.0-rc.18 (RUSTSEC-2023-0071), `bincode` (RUSTSEC-2025-0141), `paste` (RUSTSEC-2024-0436), `proc-macro-error2` (RUSTSEC-2026-0173); all pre-existing, all in `deny.toml`'s reviewed list or unmaintained-only. The MLS stack adds none.
- `cargo deny check advisories` with the fresh database: **advisories ok**.
- RustSec entries for the stack, all fixed below the pins: `hpke-rs` RUSTSEC-2026-0069/0070/0071 (aliases GHSA-g433-pq76-6cmf; fixed ≥ 0.6.0; pin 0.7.0), `libcrux-chacha20poly1305` RUSTSEC-2026-0124 (GHSA-hc3c-63hc-2r9f, "panic on overlong ciphertext buffer", fixed ≥ 0.0.8; pin 0.0.9), `libcrux-poly1305` RUSTSEC-2026-0073 (GHSA-pv9v-5j35-xwcr, fixed ≥ 0.0.5; pin 0.0.6), `libcrux-ed25519` RUSTSEC-2026-0026 (GHSA-435g-fcv3-8j26, CVE-2026-76234, fixed ≥ 0.0.6) and RUSTSEC-2026-0075 (GHSA-434v-x5qv-pmh6, "all-zero key generation on catastrophic RNG failure", fixed ≥ 0.0.7; pin 0.0.9), `crossbeam-epoch` RUSTSEC-2026-0204 (fixed ≥ 0.9.20; pin 0.9.21), `crossbeam-deque` RUSTSEC-2021-0093 and `crossbeam-utils` RUSTSEC-2022-0041 (old, fixed).
- **RustSec has no entry for `openmls` at all** (no `crates/openmls` directory). GitHub lists four OpenMLS advisories: GHSA-w62v-gv48-63rh (medium, 2026-08-25, quadratic duplicate detection, `< 0.9.0`), GHSA-rrmv-c79f-cf5r (medium, 2026-08-25, out-of-bounds panic in manual `DeserializeBytes`, `< 0.9.0`), GHSA-8x3w-qj7j-gqhf (high, 2026-02-04, improper tag validation, `< 0.7.2`), GHSA-qr9h-x63w-vqfm (medium, 2025-09-26, secret tree not persisted, `0.7.0` → `0.7.1`). `cryspen/hpke-rs`: GHSA-g433-pq76-6cmf. `cryspen/libcrux` (repository advisories): GHSA-435g-fcv3-8j26; the other libcrux GHSA ids above appear only as RustSec aliases.

**Verdict: CORRECTS.** Nothing is open at the pins (the design's conclusion stands), but (a) §3.7's advisory column names two of the provider-side advisories where the database holds eight, and (b) the design's advisory watch ("`cargo deny` green", G-M1) is blind to OpenMLS itself: none of its four advisories reached RustSec.

**Normative correction (S0-2).**
1. §3.7, row "libcrux provider 0.4.0, `hpke-rs` 0.7.0", replace the advisory cell by: "GHSA-g433-pq76-6cmf (= RUSTSEC-2026-0069/0070/0071, `hpke-rs` < 0.6.0), GHSA-435g-fcv3-8j26 (= RUSTSEC-2026-0026, `libcrux-ed25519` ≤ 0.0.5), RUSTSEC-2026-0075 (`libcrux-ed25519` < 0.0.7), RUSTSEC-2026-0124 (`libcrux-chacha20poly1305` < 0.0.8), RUSTSEC-2026-0073 (`libcrux-poly1305` < 0.0.5), RUSTSEC-2026-0204 (`crossbeam-epoch` < 0.9.20): all fixed below the pins (V10-2, database `593df8c1` of 2026-09-24)".
2. §13.1 G-M1 gains: "**OpenMLS advisories are published only as GitHub advisories** (none of GHSA-w62v, -rrmv, -8x3w, -qr9h is in RustSec, V10-2), so cargo-deny cannot see them: `mls-vendor-tests.yml` (weekly and on pin changes) also queries `repos/{openmls/openmls, cryspen/hpke-rs, cryspen/libcrux}/security-advisories` and fails when an advisory's vulnerable range contains a pinned version." §13.2's `mls-vendor-tests.yml` row gains the same sentence; R-6's mitigation gains "GHSA watch".
3. §3.1's advisory row gains the publication dates and ranges as listed above.

*Effort:* 0.25 day (S2 or CI slice). *Owner questions:* none.

---

## 3. V10-3: size of the OpenMLS stack in `libghost_client_net.so`

**Question.** What does the stack cost in the shipped library, measured the way `scripts/build-native.sh` builds it, and what is linked?

**Method.** `scripts/v10-03-size-build.sh` builds `ghost-client-net` for arm64-v8a and x86_64 as `build-native.sh` does (cargo-ndk 4.1.2, release, `strip = "symbols"`, the same path remapping, the workspace's portable-libcrux `[env]`, the libcrux packages cleaned per triple before each build), `--offline` instead of `--locked` because the patch changes the lock. Variants: the unpatched tree (`d9ff300`); the probe linked with its JNI export only; `mls-probe`; `mls-probe-pq`; and unstripped builds (`--config profile.release.strip=false`) of the baseline and of `mls-probe` for the symbol analysis (`llvm-nm -C -S --defined-only` from NDK 30; sizes summed by the first path segment of each demangled symbol — approximate, since generic instantiations land under `core`, `alloc` or the caller).

**Numbers (bytes).**

| Variant | arm64-v8a | Δ vs baseline | x86_64 | Δ vs baseline |
|---|---|---|---|---|
| baseline (`main` at `d9ff300`) | 17 931 600 | — | 19 519 400 | — |
| probe linked, no MLS (new lock) | 17 926 920 | −4 680 | 19 519 368 | −32 |
| **OpenMLS 0.9.0 + libcrux provider + GhostKv + GHOST calls** | **20 417 984** | **+2 486 384** | **22 438 568** | **+2 919 168** |
| same with `draft-ietf-mls-pq-ciphersuites` | 20 434 880 | +2 503 280 | 22 469 208 | +2 949 808 |
| unstripped: baseline / MLS | 31 965 936 / 35 705 288 | +3 739 352 | 31 430 352 / 35 321 096 | +3 890 744 |

- The budget of §3.8 (≤ +3 MiB = 3 145 728 B per ABI) holds: 2.37 MiB and 2.78 MiB. The research probe's +2.68–2.88 MB / +3.27–3.32 MB over-estimated (it shared less with the baseline).
- Symbol-size attribution of the delta (arm64-v8a; x86_64 in parentheses): `openmls` 531 KB (610), `serde_json` 355 KB (396: OpenMLS's serde entities through `GhostKv`'s JSON and the day rewrite), `libcrux_ml_kem` 296 KB (339), `libcrux_p256` 119 KB (186), the probe's own code 97 KB (133), `libcrux_ed25519` 36 KB, `libcrux_sha2` 26 KB, `rayon_core` 24 KB, `hpke_rs` 16 KB, `libcrux_aes` 16 KB, `libcrux_hkdf` 15 KB, `libcrux_chacha20poly1305` 12 KB, `tls_codec` 11 KB, `libcrux_kem` 10 KB; `core`+`alloc` monomorphisations ≈ 387 KB.
- **Linked but unused by suite 0x0003:** `libcrux_p256` and `libcrux_ecdh`'s P-256 path, and ML-KEM-512/1024 (`mlkem512`, `mlkem1024` symbols present; the baseline's DM stack links only ML-KEM-768 through the slice trait, F9 V-9): `hpke-rs-libcrux` dispatches over every KEM at run time. Together ≈ 0.42 MB (arm64) / 0.53 MB (x86_64) of the delta. Removing it would need a GHOST-written `OpenMlsCrypto` (the alternative of Q16), which is not proposed: the budget holds.
- **Dropped by the linker:** no symbol of `openmls_memory_storage`, of `openmls_libcrux_crypto::Provider`, of `test_utils` or of `fork_resolution` (0 matches on both ABIs); `skip_validation` has 3 symbols (the flag readers, never set).
- **Exports:** the only new dynamic symbol is the probe's `Java_org_ghost_crypto_bridge_MlsNative_probeMls`; the library exports 52 dynamic symbols against the baseline's 51, the extra one being that probe entry point, on both ABIs.

**Verdict: CONFIRMS** (budget), with measured numbers replacing the probe's.

**Normative correction (S0-3).**
1. §3.8 "Size": replace the bullet by: "**Measured in S0 (V10-3)** with `scripts/build-native.sh`'s recipe on `d9ff300`: +2 486 384 B (arm64-v8a) and +2 919 168 B (x86_64) stripped for OpenMLS 0.9.0, the libcrux provider, `GhostKv` and every call `ghost-client-mls` makes; the PQ feature would add 16.9 / 30.6 KB. About 0.42 / 0.53 MB of it is KEM code suite 0x0003 never runs (P-256 and ML-KEM-512/1024, linked by `hpke-rs-libcrux`'s run-time KEM dispatch). `openmls_memory_storage` is dropped by the linker. Budget ≤ +3 MiB per ABI (holds: 2.37 / 2.78 MiB); `apk-size:` reports the library per ABI." R-4's likelihood becomes "certain / low" with the measured figure; E-15 becomes **measured** in the shipped library.

*Effort:* none. *Owner questions:* none.

---

## 4. V10-4: commit and Welcome sizes with GHOST's extensions at the class caps

**Question.** Do commits with GHOST's extensions (`GhostLeaf` in every update-path leaf, `GhostCommitAad` with evidence of the right size, proposals by value, the forced path of §6.8) fit `C(4096) = 4 028` at 32 members and `C(16384) = 16 316` at 100, including §5.7's composite worst cases "in a maximally blank tree with unmerged leaves"? What do Welcomes need? If a single-proposal commit exceeds the small floor, what is the largest small class that fits?

**Method.** `core/tests/v10_04_sizes.rs` over the spike harness: real OpenMLS 0.9.0, suite 0x0003, GHOST's configuration (§3.5: `padding_size 0`, ratchet tree in the Welcome, sender ratchet (16, 1000), `max_past_epochs 64`, `RequiredCapabilities` naming 0xF0A1 and 0xF0A2, `GhostChannelContext` in the context), GHOST KeyPackages (day-aligned 84-day lifetime, `GhostLeaf`, `GhostKpBind`, capabilities 0x0003 / 0xF0A1, 0xF0A2, 0xF0A4 / Basic), every commit with `force_self_update(true)` and a `GhostLeaf` update leaf with `refresh_epoch`, and `GhostCommitAad` carrying `AdmitEvidence` (245 B) or `SwapEvidence` (rejoin 146 B, restore 279 B). Each probe commit is built by a member, validated by another member (`process_message`, change-set discarded) and dropped. Shapes: **blank** (one batch add by the owner — the owner's copath resolution then covers all n−1 other leaves, the maximal number of path ciphertexts), **populated**, **wide** (32 members in a 64-leaf tree, depth 6: 33 members, one low leaf removed), and **random histories** (60 steps of self-updates, removals by the owner and re-adds by the owner or rank 1 at 26–32 members, probing the owner's and the far member's commits every 5 steps — trees with blank parents and unmerged leaves arising naturally). KeyPackages are GHOST-shaped (395 B) or inflated with extra capability extension types to §6.2.4's bound of 1 024 B. Sizes are `MlsMessageOut` bytes, the seal's body.

**Numbers — small class, 32 members (bytes; margin to C(4096) = 4 028).**

| Commit | Blank | Margin | Populated | Wide (64 leaves) |
|---|---|---|---|---|
| empty self-update, rank 255 (far leaf) | 1 955 | 2 073 | 1 053 | 585 |
| owner's PCS commit (empty, with path) | 3 185 | 843 | 1 053 | 3 220 |
| Remove 1 | 3 110 | 918 | 1 306 | 3 110 |
| swap with rejoin evidence | 3 653 | 375 | 1 849 | 3 653 |
| swap with restore evidence | 3 786 | **242** | 1 982 | 3 786 |
| Add 1, GHOST KeyPackage (395 B), 31→32 | 3 745 | **283** | — | — |
| Add 1, KeyPackage at the 1 024 B bound, 31→32 | **4 374** | **−346** | — | — |
| Add 1, GHOST KeyPackage, 32→33 | 3 861 | 167 | 1 729 | 3 862 |
| Add 1, 1 024 B KeyPackage, 32→33 | 4 490 | −462 | 2 358 | 4 491 |
| context change: 8 committers, 3 funders, 48-byte name (446 B context) | 3 653 | 375 | 1 521 | 3 688 |
| **composite**: context change + Remove + restore swap | **4 178** | **−150** | 2 374 | 4 178 |
| composite + Add of a 1 024 B KeyPackage | 5 447 | −1 419 | 3 643 | 5 447 |
| Welcome for 1 joiner (tree included) | 8 818–9 764 (16 KiB) | | 10 824–12 059 (16 KiB) | 8 818–9 764 |

**Threshold (blank tree)** — Add with a 1 024 B KeyPackage: 3 800 B at 24 members, 3 964 at 26, **4 046 at 27**, 4 128 at 28, 4 374 at 31, 4 490 at 32; Add with a GHOST KeyPackage: 3 171 at 24 … 3 861 at 32; context change 2 997 … 3 653; restore swap 3 130 … 3 786. Each extra member adds 82 B (one HPKE ciphertext of a path secret).

**Random histories (32, 60 steps):** the largest self-update/PCS commit seen was 2 857 B and the largest context change 3 325 B — below the blank shape, as the resolution argument predicts (a non-blank node with u unmerged leaves contributes 1 + u ≤ its leaves; the committer's ciphertexts are at most n − 1 in any shape). The wide tree adds one path node (+35 B).

**Numbers — large class, 100 members (margin to C(16384) = 16 316).** Blank: rank-255 self-update 3 560, PCS 8 831, Remove 8 756, rejoin swap 9 299, restore swap 9 432, Add 9 473 (GHOST KP) / 10 102 (1 024 B KP), context change 9 299, composite 9 824, composite + Add 11 093 — **all fit, margin ≥ 5 223 B**. Populated: 936 … 3 795 B. Welcome for 1 joiner: 25 894–27 013 B (blank), 33 612–34 715 B (populated) — the 64 KiB bucket, margin ≥ 30 753 B.

**Worst Welcomes.** (a) Every leaf a KeyPackage leaf at the 1 024 B bound (a KeyPackage leaf stays in the tree until its member updates): **32 885 B at 32 members** (64 KiB bucket, not the 16 KiB of §5.7's table) and **103 061 B at 100 members — NO_FIT**: no Welcome can be sent, so nobody can join or rejoin. (b) Leaves inflated by their own members (`v10_04_leaf_inflation_by_self_updates_100`): a rank-255 member's modified client adds an unknown extension (type listed in its own capabilities) to its update-path leaf in an empty self-update; the largest that still fits C(16384) adds 12 746–12 809 B. After 1, 2, 3, 4 such members the next one-joiner Welcome is 39 121, 51 891, 64 792, **77 625 B (NO_FIT)** — four members lock joins out of a 100-member channel (three in a populated tree). OpenMLS accepts every one of these self-updates, and CO-2 as written checks only the commit's size.

**Verdict: CORRECTS.**
- With the GHOST-shaped KeyPackage, **every single-proposal commit fits the floor at both caps**, so Q3's small class at 32 stands and is not re-asked; the tightest margins are 242 B (restore swap) and 283 B (Add at 31→32).
- With §6.2.4's bound of 1 024 B, **a single Add exceeds C(4096) from 27 members** (a class violation §5.7 says S0 must rule out) and a 100-member tree of such leaves cannot be welcomed.
- The composite of §5.7 (context + Remove + swap) is 4 178 B > 4 028: it must split, which §5.7's rule already does; the protocol review's 3.8–4.3 KB estimate was right.
- "Unmerged leaves" do not make commits larger than the blank tree; the worst shape is the committer whose whole copath is blank (the owner right after a batch add, or any member after removals blanked its copath).
- Welcomes are not bounded by anything in the design today (leaf inflation by joiners or by members themselves).

**Normative correction (S0-4, KeyPackages and the size table).**
1. §6.2.4 (B), replace "exactly **one** leaf extension (`GhostLeaf` with a valid `box_pk` and `refresh_epoch = 0`), total size ≤ 1 024 bytes" by: "**the canonical GHOST KeyPackage**: capabilities exactly versions [mls10], ciphersuites [0x0003], extensions [0xF0A1, 0xF0A2, 0xF0A4], proposals [] (OpenMLS's defaults only), credentials [Basic], in that order; leaf extensions exactly [`GhostLeaf` with a valid `box_pk` and `refresh_epoch = 0`]; KeyPackage extensions exactly [`GhostKpBind`]; no GREASE values. Its encoding is 395 bytes with OpenMLS 0.9.0 (V10-4); `ch_kp_golden` pins that size per OpenMLS pin (G-M7), and a KeyPackage of any other size is refused. (Round 10c's bound of 1 024 bytes let a single Add exceed C(4096) from 27 members and made a 100-member tree unwelcomable, V10-4.)" The `JoinRequest` codec (§5.6) refuses `kp_len ≠ 395`.
2. §5.7, replace the measured-sizes table by the two tables above (32 and 100 members, blank / populated / wide, GHOST extensions and evidence, 2026-09-25, `v10_04_sizes.rs`) and the note "≈ 3.1 KB interpolated, S0 measures" by "measured: 3 110 B (blank), margin 918 B". Replace "Welcomes … 16 KiB (small), 64 KiB (large)" by "16 KiB (small, ≤ 12.1 KB with canonical leaves), 64 KiB (large, ≤ 34.7 KB); both bounded only because every leaf is canonical (S0-5)". The rule's last sentences become: "S0 measured the composite worst cases (V10-4): with canonical KeyPackages every single-proposal commit fits at both caps (tightest: restore swap 3 786 B at 32, margin 242 B); the composite of a context change, a Remove and a swap is 4 178 B at 32 and is split by this rule. Q3 is not re-asked."
3. G-M7 gains golden **sizes**: the five small-cap single-proposal commits of the table (blank, 32) and the canonical KeyPackage, re-measured at every OpenMLS bump; a bump that eats the 242-byte margin fails the gate.
4. D15's "(S0 measures, V10-4)" and R-19 are closed by these numbers; E-14 and E-21 become **measured** (in the spike, with GHOST's extensions).

**Normative correction (S0-5, leaves a commit installs).**
1. CO-2 gains, after the leaf-continuity clause: "**every leaf the commit installs is canonical**: an update-path leaf has exactly the canonical capabilities of §6.2.4 and exactly one extension, `GhostLeaf` (V10-4: four rank-255 self-updates each adding 12.8 KB to their own leaf, every one within C(16384), made the next 100-member Welcome 77 625 B, beyond C(65536), so no one could join); a KeyPackage an Add or a swap carries is the canonical KeyPackage (§6.2.4). Both are functions of the commit."
2. §5.4's `GhostLeaf` paragraph gains "and it is the leaf's only extension (CO-2)".
3. L8-C11 is narrowed: "a malicious member can send large valid objects up to 64 KiB per blob (post content), but cannot enlarge the tree: leaves are canonical (CO-2)"; SRLabs S0-1's leaf-node vector (Appendix A) is closed for channels by the same rule.
4. A mutant **MM-38** ("CO-2 accepts a non-canonical update-path leaf") with its killer GV (an inflated self-update is refused) and the Welcome-size assertion of SCN-M20 (every Welcome ≤ C(65536)).

*Effort:* 0.5 day (S4/S5: the canonical checks are byte comparisons). *Owner questions:* none; Q3 keeps its default.

---

## 5. V10-5: the cost of the value-semantics storage adapter

**Question.** How many rows does a call load, how large is the change-set it returns, how does the write amplification grow with retained past epochs, at 32 and 100 members, and what does a trial settle (CO-3) cost?

**Method.** `core/src/kv.rs` implements `GhostKv` as §3.4 specifies it: an in-memory map loaded from the channel's rows; every write, append and delete recorded into a net change-set; group-scoped vs global rows by method (every method that takes a `GroupId` is group-scoped; a group id other than the call's channel is refused); values wrapped as `nonce(12) ‖ ChaCha20-Poly1305(state key, AD = "ghost/v1/mls-kv" ‖ scope ‖ channel_id ‖ SHA-256(k), v)`; the `added_at` day rewrite in `write_message_secrets` (a `LayoutDrift` error when `message_secrets.added_at` is missing). Values are OpenMLS's serde entities as JSON (the memory provider's format). The harness (`Device::call`) runs every operation with value semantics: unwrap every stored row, load, run, wrap the change-set, apply only on success. `core/tests/v10_05_adapter.rs` measures a member M at 0, 2, 8 and 64 retained past epochs (`max_past_epochs(64)`, §3.5), blank and populated, 32 and 100 members, for: receive a 200-byte post, encrypt one, the validation run of a commit (CO-2, dry), a trial settle (process + merge + open one successor post, all discarded), the settle, M's own commit and merge, a load-only call, and `sweepPast(2)`. The same runs with an experimental **split** mode of `GhostKv` (past epochs stored one row per epoch, unchanged rows not rewritten) test a fix.

**Numbers — structure.**
- **Methods.** The `StorageProvider` trait has 72 `fn`s (`ot:src/storage.rs`), of which **53 are required in the P0 feature set** (41 group-scoped, 12 global) plus the default `version()`; the other 18 exist only under `extensions-draft` (3) and `virtual-clients-draft` (15), both forbidden by §3.2.
- **Rows.** An active member holds **11 group-scoped rows** per channel (`ConfirmationTag`, `EpochKeyPairs`, `EpochSecrets`, `GroupContext`, `GroupState`, `InterimTranscriptHash`, `MessageSecrets`, `MlsGroupJoinConfig`, `OwnLeafNodeIndex`, `ResumptionPsk`, `Tree`) and **no global row**: the KeyPackage's rows (the bundle with its private keys) exist only from `keyPackage` until the Welcome is processed; OpenMLS stores no signature key (GHOST's signer is its own).
- **Row sizes (JSON, blank):** `Tree` 40.9 KB (32) / 125.1 KB (100), 51.2 KB populated at 32; `MessageSecrets` 2.4 KB / 4.3 KB with no past epoch and **+18.6 KB (32) / +52.9 KB (100) per retained past epoch**: OpenMLS keeps every past epoch's secret tree *and its full member list* inside that one row (`om:src/group/mls_group/past_secrets.rs`, `EpochTree { epoch, message_secrets, leaves: Vec<Member> }`).

**Numbers — per call (blank; bytes; host times under 100 % load).**

| n | retained past epochs | rows loaded (plain) | receive post: change-set | receive post | trial settle (merge + 1 successor) | settle |
|---|---|---|---|---|---|---|
| 32 | 0 | 47 481 | 3 359 | 0.47 ms | 3.3 ms | 2.7 ms |
| 32 | 2 | 84 744 | 40 548 | 1.6 ms | 9.6 ms | 4.6 ms |
| 32 | 8 | 196 183 | 151 917 | 4.0 ms | 13.8 ms | 8.2 ms |
| 32 | 64 | 1 234 810 | **1 190 544** | 33.6 ms | 101 ms | 59.8 ms |
| 100 | 0 | 134 255 | 5 533 | 1.2 ms | 28.8 ms | 11.9 ms |
| 100 | 2 | 240 175 | 111 410 | 17.1 ms | 48.5 ms | 29.8 ms |
| 100 | 8 | 557 501 | 428 738 | 30.5 ms | 88.6 ms | 48.5 ms |
| 100 | 64 | 3 518 546 | **3 389 803** | 214 ms | **1 139 ms** | 708 ms |

- A settle writes 10 rows and deletes 3 (66 KB at 32, 187 KB at 100 with no past epoch, plus the whole `MessageSecrets`). The validation run of a commit also produces a change-set (the rewritten `MessageSecrets`), which CO-2 discards — confirmed necessary: re-processing the same commit at the settle succeeds only because the validation's ratchet consumption was not written.
- Wrapping is 5–15 % of a call; the rest is JSON (de)serialisation of the whole state.
- **Split mode:** a post's change-set becomes **3.3–3.5 KB at 32 and 5.5–5.7 KB at 100 whatever the retention** (64 epochs included), because a post changes only the current epoch's secret tree; `sweepPast(2)` then deletes 62 rows. The **load** (and so the CPU time) still grows with retention: every call parses all retained epochs (receive post at 64 retained: 69 ms at 32, 141–708 ms at 100 on the loaded host).
- Populated at 32 (31–64 retained epochs after the populate): 0.58–1.19 MB per post; split: 3.4–3.5 KB.

**Verdict: CORRECTS.** The adapter works as specified (value semantics, change-sets, scopes, wrapping, the day rewrite all exercised, and the KAT replay of §12 passes through it, V10-12). But (a) §3.4 counts 72 methods; (b) the write amplification is not a per-row matter the design can ignore: with the hard cap of 64 past epochs a received post can write 3.4 MB to SQLCipher in a 100-member channel and the trial settles of CO-3 (up to 8 per settle, §6.3.5) can take seconds on the host and tens of seconds on a low-end phone (×15–25, F9's factor); (c) R-3's figures (57–261 KB) describe 2 retained epochs only.

**Normative correction (S0-6).**
1. §3.3 and §3.4 point 1: "`StorageProvider` (**53 methods** in GHOST's feature set, 41 group-scoped and 12 global, plus `version()`; the trait's other 18 exist only under the forbidden `extensions-draft` and `virtual-clients-draft` features, V10-5)"; `GhostKvScopeTest` enumerates the 53 and a compile-time check fails if a forbidden feature adds methods.
2. §3.4 gains point 8, "**Past epochs, one row each (V10-5; recorded deviation like point 5).** `write_message_secrets` stores the `MessageSecretsStore` as a head row (the store with `past_epoch_trees` replaced by its epoch numbers) and one row `(channel_id, "MessageSecretsPast" ‖ epoch)` per retained past epoch; a row whose bytes did not change is not rewritten; `message_secrets` reassembles them. A post then writes 3.3–5.7 KB at 32–100 members whatever the retention, instead of the whole store (40 KB … 3.4 MB). It reads OpenMLS's serde layout (`past_epoch_trees[].epoch`); G-M7's golden `MessageSecrets` covers it, and a missing field is `STATE_CORRUPT`."
3. §3.5 "Past epochs": `max_past_epochs(64)` becomes **`max_past_epochs(16)`** (hard cap); §8.3's count rule is unchanged (typically 2–8 epochs in 2 days). §6.3.6's declared losses gain "a post of an epoch more than 16 epochs behind the member's current one".
4. R-3: "measured (V10-5): every call loads the whole channel state (47 KB at 32 members and 134 KB at 100 with no past epoch, +18.6 / +52.9 KB per retained past epoch) and parses it; receive-post 1.6–4.0 ms at 32 and 17–30 ms at 100 on a loaded host with 2–8 retained epochs; a trial settle 10–14 ms / 49–89 ms."
5. **Q18 re-asked**: "Keep value semantics (every call reloads the channel's rows) with past epochs split into rows and a cap of 16, or add the version-checked native cache now? Measured cost of value semantics on a loaded host: 17–30 ms per received post at 100 members with 2–8 retained epochs, 49–89 ms per trial settle; a low-end phone is estimated 15–25 times slower." Default: **value semantics, split, cap 16**; the cache is decided after the device step measures it (V10-10).

*Effort:* 1 day in S2 (split rows, their golden, the cap). *Consequences:* §9 (`mls_kv` holds ≤ 11 + 16 rows per channel), CS-C8 (bounded state), T33's state scan (the per-epoch rows also carry day-rewritten stamps).

---

## 6. V10-6: determinism under a seeded getrandom

**Question.** With the process-global ChaCha20 stream behind getrandom's custom backend and `rayon` at one worker, do two runs of a scripted world produce byte-identical commits, Welcomes and state (a first probe of §19.10's S2 work)?

**Method.** Feature `det` of the spike defines `__getrandom_v03_custom` (the symbol getrandom 0.4.3's `custom` backend calls, `getrandom-0.4.3/src/backends/custom.rs`): one ChaCha20 stream under a mutex, keyed by the world seed, logging the drawing thread. The example `det_world` (built with `RUSTFLAGS='--cfg getrandom_backend="custom"'`) creates a channel of 8 (batch add, Welcome), sends 3 posts, a self-update, a remove, an add with its Welcome and a remove against a tree with unmerged leaves, all with value semantics, and prints the SHA-256 of every message and of every member's full row set. It ran twice in two separate processes per configuration.

**Numbers.**
- Graph: getrandom **0.4.3 is the only getrandom in the spike's graph and in `ghost-dm-host`'s normal host graph** (0.2.17 is in the lock for other targets only), so one custom symbol covers every draw; `rand` 0.10's `SysRng` (the provider's DRBG seed and reseed, `hpke-rs-libcrux`'s PRNG) goes through it.
- **One rayon worker, same seed, two processes: identical output** — every message (e.g. self-update 1 065 B `a89df523f4249d7f`, Welcome 2 791 B `a590f4c0b7d9895f`), every member's rows, equal epoch authenticators. Another seed: everything differs from the channel id on.
- **Draws: 270 (8 640 B), 172 on the main thread and 98 on a second thread** — the rayon worker, where `treekem.rs` seals path secrets with an HPKE PRNG seeded from `SysRng` (design §3.3 confirmed).
- **Rayon's default pool (24 threads), same seed, two processes: the posts are identical but every commit, Welcome and state differs** — the workers draw in racy order.
- **One worker but the `added_at` day rewrite switched off** (`GHOST_SPIKE_NO_DAY_REWRITE=1`): every message identical, **every member's rows different** — OpenMLS stamps `SystemTime::now()` into `MessageSecrets`.
- `std`'s `HashMap` keys (not drawn through getrandom) do not reach any output in this script.

**Verdict: CONFIRMS** the design's approach (§12.1, §19.10), with two preconditions the design names only in part.

**Normative correction (S0-7).**
1. §12.1 "Determinism" gains: "V10-6 confirmed the approach in a first probe (two processes, byte-identical messages and state) and named its preconditions: (a) `rayon` at **one** worker (with the default pool the runs differ); (b) the **`added_at` day rewrite** of §3.4 point 5 (without it the stored rows differ between runs; the rewrite is therefore a determinism requirement as well as T33's); (c) a **single getrandom major** in the host graph (today 0.4.3 only), whose custom symbol is `__getrandom_v03_custom`; G-R2 checks that the host library's normal graph contains no other getrandom version, and a second version would need its own hook."
2. §3.6 "Threads": "One worker is necessary … (V10-6: with the default pool, two runs of one seed differ; 98 of 270 draws happen on the worker)".

*Effort:* none beyond S2's planned work. *Owner questions:* none.

---

## 7. V10-7: portable libcrux in the provider's crates

**Question.** Do the libcrux crates the provider adds build portable-only on both triples, is §19.23's `libcrux-aes` hazard real, and should G-R3's inline rule be extended or extracted into a script?

**Method.** (1) Every added libcrux crate's manifest and sources read for build scripts, SIMD features, `target_feature`, `std::arch`/`core::arch` and CPU detection. (2) The `libcrux-aes` build script exercised on the host in a scratch target directory: variables set to "0", then the workspace `[env]` ("1") without a clean, then `cargo clean -p libcrux-aes`, then "0" again without a clean — reading `build/libcrux-aes-*/output` after each step. (3) Every Android build of V10-3 cleaned `libcrux-ml-kem`, `libcrux-sha3`, `libcrux-intrinsics` and `libcrux-aes` per triple first and printed their build-script outputs afterwards. (4) The unstripped libraries searched for SIMD-named symbols.

**Numbers.**
- Build scripts: of the provider's crates only **`libcrux-aes` 0.0.9 has one** (`build = "build.rs"`): it emits `cargo:rustc-cfg=feature="simd128"` on aarch64 and `feature="simd256"` on x86_64 unless `LIBCRUX_DISABLE_SIMD128/256`, and has no `rerun-if-env-changed`. `libcrux-aead`, `-chacha20poly1305`, `-poly1305`, `-ed25519`, `-hkdf`, `-hmac`, `-hmac-drbg`, `-sha2`, `hpke-rs-libcrux` and `openmls_libcrux_crypto` have no build script and no SIMD or arch code.
- Stale cfg (host, x86_64): **simd256 → still simd256 after the variables changed → portable after the clean → still portable after the reverse change** — exactly F9 V-6's sequence for the other three packages.
- Android builds (6 builds, both triples): every `libcrux-{ml-kem,sha3,intrinsics,aes}` build output has **0 `cargo:rustc-cfg` lines**.
- Symbols (unstripped, both ABIs): no libcrux SIMD implementation; the only libcrux symbols with SIMD names are `libcrux_platform::platform::simd128_support` / `simd256_support` (CPU-query helpers, x86_64). The NEON/AVX2 symbols present belong to RustCrypto `chacha20`, `curve25519-dalek`, `memchr`, `ring` and `simd_adler32`, all in the baseline.
- AES-GCM (the only user of `libcrux-aes`) is reachable only through suites 0x0001 and the AES PQ suites, which GHOST never uses; it is linked because the provider dispatches on the AEAD at run time.

**Verdict: CONFIRMS** §19.23 (the `libcrux-aes` hazard is real and the clean lists must name it). **S0's decision** (asked by §13.1 G-M9 and §19.10): **extract the script**. The inline rule already exists in three workflows (`ci.yml:254`, `dm-emulator.yml:149,165,172,176-189`, `dm-privacy-gate.yml:114,197`), each with its own package list, and Phase 10 adds four packages' worth of builds (`mls-vendor-tests`, the channel gates, the emulator smoke); one script avoids five diverging copies.

**Normative correction (S0-8).**
1. §13.1 G-M9 becomes: "**`ghost/scripts/gates/libcrux-portable.sh`** (extracted in S2 from the inline rule of `dm-emulator.yml:176-189`, V10-7): `--clean <target-dir> <triples…>` runs `cargo clean -p libcrux-ml-kem -p libcrux-sha3 -p libcrux-intrinsics -p libcrux-aes` per triple; `--check <build dirs…>` fails when any `build/<pkg>-*/output` of those four packages carries `feature="simd128"` or `feature="simd256"`, or when none exists. Every workflow that builds a client graph calls both (`ci.yml`, `dm-emulator.yml`, `dm-privacy-gate.yml`, `mls-vendor-tests.yml`, the channel gates); a negative fixture (a target directory first built without the variables) is in `self-test.sh`. `libcrux-aes` is the only provider crate with a SIMD build script (V10-7)."
2. §19.23's `libcrux-aes` bullet: "confirmed (V10-7: simd256 → simd256 → portable after the clean → portable)".

*Effort:* 0.5 day (S2 gates). *Owner questions:* none.

---

## 8. V10-8: the bootstrap in the Welcome's GroupInfo

**Question.** Does `GhostBootstrap` (0xF0A3) passed through `CommitBuilder::create_group_info_with_extensions` reach the GroupInfo inside the Welcome, can the joiner read it, and does the committer's GroupInfo signature authenticate it?

**Method.** `core/tests/v10_08_bootstrap.rs`: a committer adds a joiner with the bootstrap as a GroupInfo extension; the joiner reads `ProcessedWelcome::unverified_group_info().extensions()`, then `JoinBuilder::build()` (with `skip_lifetime_validation()`) and `into_group`. Authentication: the committer's signer corrupts the n-th signature of the next commit (n = 1 … 4) and the joiner's result is recorded. Two more cases: the same with `create_group_info(false)` after the extensions, and a plain commit's exported GroupInfo.

**Numbers.**
- The bootstrap (45 B) arrives in the Welcome's GroupInfo and the joiner joins (Welcome 2 007 B at 4 members; the joiner's epoch authenticator equals the committer's).
- Corrupted signature #1 (the update-path leaf): the joiner refuses (`PublicGroupError(TreeSyncError(RatchetTreeError(InvalidNodeSignature)))`), and so do members (`ValidationError(UpdatePathError(SignatureError(…)))`). #2 (the commit's FramedContent): the joiner **accepts** — a joiner never sees the commit. **#3 (the Welcome's GroupInfo): the joiner refuses with `PublicGroupError(InvalidGroupInfoSignature)`**. #4 (the exported GroupInfo): the joiner accepts.
- `create_group_info_with_extensions` also turns on OpenMLS's **exported** GroupInfo (with the ratchet tree and an `ExternalPub` extension; 1 869 B at 4 members). With `create_group_info(false)` after it, no exported GroupInfo is built and the bootstrap still reaches the Welcome.
- With `use_ratchet_tree_extension(true)` (§3.5) **every** commit, with or without Adds, builds an exported GroupInfo by default (1 255 B at 3 members; OpenMLS derives the external key pair for it). `create_group_info(false)` turns it off.
- Upstream's own test of `create_group_info_with_extensions` (`openmls/src/group/tests_and_kats/tests/group.rs:905-906`) is `#[ignore]`d at the tag commit, so GHOST's test is the only coverage of this path.

**Verdict: CONFIRMS.** The primary path works and is authenticated; the fallback of §5.4/§5.6 is not needed.

**Normative correction (S0-9).**
1. §5.4, replace "**if S0 confirms … (V10-8)** … Otherwise it travels next to the Welcome …" by: "It travels in the Welcome's encrypted GroupInfo through `CommitBuilder::create_group_info_with_extensions` (confirmed by V10-8), authenticated by the committer's GroupInfo signature: a Welcome whose GroupInfo signature is wrong is refused (`InvalidGroupInfoSignature`). The joiner reads it from `ProcessedWelcome::unverified_group_info()` and uses it only after `JoinBuilder::build()` succeeded, which verifies that signature." The `K_boot(e)` fallback is withdrawn from P0.
2. §5.2, the `K_boot(e)` row is deleted. §5.6 `WelcomeBlob` loses `boot_flag` and the bracketed field: `WelcomeBlob = version(1) = 1 ‖ kp_ref_len(u8) ‖ kp_ref ‖ welcome_len(u24_be) ‖ welcome`. §10.2 fn 5's outputs: "bootstrap (g, `G_g` env), authenticated by the GroupInfo signature".
3. §10.2 fn 9 and §3.5 gain: "every commit calls `create_group_info(false)` after `create_group_info_with_extensions` (when a Welcome carries a bootstrap) — GHOST never builds or keeps OpenMLS's exported GroupInfo, which contains an `ExternalPub` key (V10-8)". G-M2 gains a source scan refusing `export_group_info` and `into_group_info*`.
4. Mutant PC-17 becomes "the joiner uses the bootstrap before `build()` verified the GroupInfo (or from a Welcome whose GroupInfo signature failed)", killed by JN's re-signed-bootstrap case; the V10-8 test (signature #3 corrupted) moves into `ghost-client-mls` and G-M7 as a regression test, since upstream's own test is ignored.

*Effort:* −0.25 day (less code). *Owner questions:* none.

---

## 9. V10-9: OpenMLS's post-quantum suites with the libcrux provider (evidence for Q2)

**Question.** Do 0x004D (OpenMLS's X-Wing code point) and 0x004F (the WG draft's provisional TBD1) work with the libcrux provider, and what do GHOST-shaped commits cost?

**Method.** `core/tests/v10_09_pq.rs` (feature `pq`): for 0x004D, 0x004F and 0x004E (TBD2, also present in `ot:src/types.rs`), `supported_ciphersuites()` and `supports()`, then a blank world of 20 and of 32 members with GHOST's configuration and extensions: a PCS commit, a Remove, an Add with evidence (and its Welcome), each validated by a member, then a self-update merged by all and a post decrypted end to end.

**Numbers (bytes).**

| Suite | listed | `supports()` | KeyPackage | n | PCS | Remove | Add + evidence | Welcome | end to end |
|---|---|---|---|---|---|---|---|---|---|
| 0x004D X-Wing, ChaCha20 | yes | Ok | 2 765 | 20 | 30 006 | 28 842 | 33 018 | 37 986 | yes |
| | | | | 32 | 44 060 | 42 896 | 48 291 | 56 447 | yes |
| 0x004F ML-KEM768+X25519, AES-128-GCM | **no** | Ok | 2 765 | 20 / 32 | same as 0x004D | | | | yes |
| 0x004E ML-KEM768+X25519, AES-256-GCM, SHA-384 | **no** | Ok | 2 765 | 20 | 30 361 | 29 180 | 33 389 | 38 162 | yes |
| | | | | 32 | 44 619 | 43 438 | 48 866 | 56 639 | yes |

- Every PQ commit needs the 64 KiB bucket already at 20 members; each member adds ≈ 1.17 KB to a blank-tree commit, so an Add stays within C(65536) up to ≈ 46 members and a Welcome up to ≈ 38.
- The PQ KeyPackage (2 765 B) is larger than §6.2.4's 1 024 B bound (and than S0-4's canonical size).
- The feature adds no package and 16.9 / 30.6 KB of code (V10-3).

**Verdict: CONFIRMS** D3 and §4.2 (classical in P0) with corrected numbers: the WG code points work with the libcrux provider (the design said "untested"), which does not change the decision (TBD code points, outside the audit, 64 KiB blobs from 20 members).

**Normative correction (S0-10).** §4.1 "Sizes" and D3's parenthesis: replace the research figures by "measured with GHOST's extensions (V10-9, blank tree): KeyPackage 2 765 B; at 20 members a Remove is 28.8 KB, a PCS commit 30.0 KB, an Add 33.0 KB and its Welcome 38.0 KB; at 32 members 42.9 / 44.1 / 48.3 / 56.4 KB; every PQ blob needs the 64 KiB bucket, and C(65536) caps a channel near 46 members (Adds) and 38 (Welcomes)". §4.1's sentence on 0x004F becomes "the provider does not list 0x004F or 0x004E but accepts them, and both work end to end at 20 and 32 members (V10-9)". Q2's text replaces "cap ≈ 32" by "64 KiB blobs from 20 members, cap ≈ 38–46". *Effort:* none. *Owner questions:* Q2 unchanged.

---

## 10. V10-10: timings on the host, the emulator and a low-end device

**Question.** How long do the native calls take at 20 and 100 members on the host, and on one low-end Android device if available?

**Method.** `core/tests/v10_10_timings.rs`: blank worlds of 20 and 100 members and a populated one of 20, retention swept to 2 past epochs at the measured members, rayon at one worker, value semantics with wrapping; each operation repeated 15 times on the same state (dry calls restore the rows); min / median / max. The same run twice, the host at 100 % CPU both times. `core/examples/device_probe.rs`, built with cargo-ndk for x86_64 and arm64, pushed with `adb` to the **x86_64 emulator** (AVD `ghost-dm-api29`, Android 10, WHPX, 4 cores, 4 GiB, port 5574; the API 35 AVD was in use by another session and was left alone) and run from `/data/local/tmp`; the pushed binary's SHA-256 (`96c1e890…1019`) equals the built one. No low-end device is attached to this host.

**Numbers — host (loaded; medians of the second run, ms).**

| Operation | n = 20 blank | n = 20 populated | n = 100 blank |
|---|---|---|---|
| keyPackage | 0.22 | 0.17 | 0.37 |
| commit: PCS self-update | 6.54 | 4.38 | 33.70 |
| commit: Add 1 + Welcome | 8.79 | 4.73 | 30.66 |
| commit: Remove 1 | 7.16 | 4.37 | 28.46 |
| validation run (CO-2) | 3.66 | 3.53 | 8.39 |
| settle (process + merge) | 3.99 | 3.43 | 12.91 |
| welcomeJoin (1 joiner) | 3.56 | 3.39 | 13.43 |
| encrypt post (1 000 B) | 1.40 | 0.91 | 3.89 |
| decrypt post (1 000 B) | 1.74 | 1.33 | 3.85 |

A first run under the same load (before the retention sweep was added) gave medians between 0.4 and 1.0 times these; no host figure bounds a call.

**Numbers — x86_64 emulator (API 29; medians of 9, ms).** The 3-member cycle (create, admit, post and AAD check, self-update, remove, add; epoch authenticators equal): **OK** in 27.9 / 54.8 ms. n = 20: PCS commit (2 201 B) 8.30, settle 4.25, decrypt 1.00, encrypt 1.87. n = 100: PCS commit (8 831 B) 30.74, settle 25.05, decrypt 7.60, encrypt 7.72; building the 100-member world 2.67 s.

**Verdict: INCONCLUSIVE** for devices (none available; an x86_64 emulator on this host is not a low-end phone and runs no arm64 code), recorded for the host and the emulator. What was established: OpenMLS, the libcrux provider and `GhostKv` **run on Android's bionic libc** (x86_64) through every call with correct results — the first execution of the stack on Android in GHOST (R-9: upstream builds Android targets without testing them). On F9's 15–25× factor, a 100-member channel would cost 0.5–0.85 s per commit built, 0.2–0.3 s per settle and 60–100 ms per post on a low-end phone (estimate, not a measurement).

**Normative correction (S0-11).**
1. §12.12, row "performance on low-end phones": "host timings (V10-10, loaded host) and the x86_64 emulator (API 29): at 100 members a commit 29–34 ms, a settle 13–25 ms, a post 4–8 ms; low-end phones **not measured**".
2. §12.11 and Q20's device step: the two arm64 phones run the S2 successor of `device_probe` (the 3-member cycle and the 20/100-member timings) before any distribution; its output joins the device checklist, and Q18's cache decision (S0-6) uses it.
3. R-3's residue: "unmeasured on devices until the device step; host and emulator figures in V10-10".

*Effort:* none (the device step is an owner action). *Owner questions:* Q20 (device step) unchanged.

---

## 11. V10-11: OpenMLS's wall-clock sites against the anchored virtual time

**Question.** Are KeyPackages from each end of a world's day range accepted on the host clock (§12.1: first virtual day ≥ host − 79, last ≤ host + 3)? How does a lifetime failure surface, and can GHOST map it to `LIFETIME_PENDING` as CO-2 requires ("refused **only** for a KeyPackage lifetime")? Joins?

**Method.** `core/tests/v10_11_lifetimes.rs`. (a) KeyPackages made on virtual days host−81 … host+6 with GHOST's lifetime `[d−4, d+80]`, parsed by a committer (`KeyPackageIn::validate`). (b) An Add of a KeyPackage valid for 3 more seconds, committed while valid; receivers validate before and after expiry; the same commit also built with signature #1 (update-path leaf) or #2 (FramedContent) corrupted. (c) A KeyPackage valid only from now + 1 h. (d) A 100-year lifetime. (e) A member admitted with a 3-second KeyPackage that never updates, then a later joiner's Welcome with and without `skip_lifetime_validation()`, and an existing member processing that commit.

**Numbers.**
- (a) Accepted from host−79 to host+4; refused at host−80 (`LifetimeError(Expired { not_after: …, now: … })`) and host+5 (`NotValidYet`). §12.1's range holds with a day of margin at the top.
- (b) Before expiry: valid; after expiry the receiver's error is **`ValidationError(KeyPackageVerifyError(LifetimeError(Expired { … })))`** — typed, so a mapping exists. **Ordering:** with the update-path leaf signature also corrupted, the receiver reports **only the lifetime error**; with the FramedContent signature corrupted it reports `InvalidSignature` first. OpenMLS validates each Add's KeyPackage (`KeyPackageIn::validate`, `om:src/key_packages/key_package_in.rs:195-197`, reached from `om:src/messages/proposals_in.rs:177` while the content is decoded) after checking the commit's signature but **before** verifying the update path, the proposal set, the capabilities and everything GHOST's CO-2 checks afterwards: a lifetime refusal says nothing about the rest of the commit.
- (c) A KeyPackage not yet valid: `LifetimeError(NotValidYet …)` at the committer's parse.
- (d) **OpenMLS never checks the span**: `Lifetime::has_acceptable_range()` (`om:src/key_packages/lifetime.rs:116`) is called nowhere in the crate; a 100-year KeyPackage is accepted by the committer and its Add by receivers. (All 1 550 Add KeyPackages of the WG passive-client vectors carry `[0, u64::MAX]`, V10-12.)
- (e) The default `JoinBuilder` refuses a tree with an expired never-updated leaf (`PublicGroupError(LeafNodeValidation(Lifetime(Expired …)))`); with `skip_lifetime_validation()` the join succeeds; existing members process the commit (the tree's old leaves are not re-validated).

**Verdict: CORRECTS.** The range (a) and the join rule (e) are confirmed. But CO-2's rule "if OpenMLS refuses it **only** for a KeyPackage lifetime (`LifetimeError`) … the candidate is *lifetime-pending*: **ranked as valid**, never merged, and the member is `clock_blocked` while it would win" cannot be implemented as stated: the refusal masks other defects (measured), so a committer can send an otherwise-invalid commit carrying an expired KeyPackage and every member whose clock rejects it — for an expired KeyPackage, every correct clock — ranks it as valid and stalls for as long as it would win. And the span and day-alignment checks that §6.2.4 (B) and §6.2.5 leave to the admitting committer and to joins are not made by OpenMLS for received Adds at all, while CO-2 (A) does not make them either.

**Normative correction (S0-12).**
1. CO-2 (A) gains: "every KeyPackage an Add or swap carries has a lifetime whose bounds are whole UTC days, whose span is exactly 84 days (`[d − 4, d + 80]`), and whose d is within `[commit_day − 7, commit_day + 3]` (the admission window of §6.2.4 (B) seen from the commit), with `commit_day` the day of the commit's `GhostCommitAad.commit_minute` (V10-11: OpenMLS never checks the span; a 100-year KeyPackage is accepted). These are functions of the commit."
2. CO-2's lifetime clause is replaced by: "If OpenMLS refuses the commit with `KeyPackageVerifyError::LifetimeError` (the device-clock site of §3.6), the commit's validity is **unknown**: OpenMLS checks KeyPackage lifetimes before the update path and the proposal set, so the refusal masks any other defect (V10-11). Such a candidate is **lifetime-pending**: it is ranked by `(rank, hash)` but is never merged, never counted as valid in CO-3's successor counts, and never lets the member settle past it; the member is `clock_blocked` while it would win. It stops being pending when (a) OpenMLS accepts it (the device clock moved or was fixed), after which the full validation runs and decides, or (b) the member's **trusted** day is past the KeyPackage's `not_after` day, when it is treated as **invalid** (an expired KeyPackage is not a clock problem) and the next candidate decides. Members whose trusted days differ by up to σ (F7:58) can decide (b) on different sides of `not_after` for a KeyPackage admitted within σ of its expiry, which an honest committer never does (§6.2.4 (B) admits a KeyPackage at least 73 days before its expiry); the residue is declared in L8-C20."
3. §3.5 row "Leaf lifetime validation", §3.6's clock paragraph and §19.4 rule 2 are aligned with point 2; §3.5 row "KeyPackage lifetime" drops "within OpenMLS's maximum range of 84 d + 1 h" (OpenMLS does not enforce it) and states that GHOST enforces the exact span in CO-2 (A) and at joins.
4. EM-3 gains the adversary "a committer's otherwise-invalid commit carrying an expired KeyPackage" (property: no member merges it; members stall at most until their trusted day passes `not_after`); MM-27 is redefined as "a lifetime-pending candidate is ranked or counted as valid" with that killer; a new mutant **MM-39** "CO-2 does not check the KeyPackage lifetime span" killed by GV (a 100-year KeyPackage in an Add is refused).
5. §12.1's range sentence gains "(V10-11: KeyPackages made on host − 79 … host + 4 are accepted at the host clock)".

*Effort:* 0.5 day (S5, CO-2 and EM-3). *Owner questions:* none (L8-C20's wording changes; the upstream request for an injectable time source, F-5, stands).

---

## 12. V10-12: the MLS WG passive-client vectors through `GhostKv`

**Question.** Does the WG's passive-client replay pass through `GhostKv` under value semantics (the `ghost-client-mls-kat` crate of §10.1), and which vectors and epochs are valid on the host clock?

**Method.** `scripts/v10-12-fetch-vectors.sh` fetches `passive-client-welcome.json`, `passive-client-handling-commit.json` and `passive-client-random.json` from the openmls repository at `3a3e35de…` and verifies each against the tree's git blob id (`15bbfcf0…`, `c702dcc3…`, `ea20d752…`; SHA-256 `92ebb04b…849c`, `b24949fd…da21`, `0095d863…d3c1`). `kat/tests/passive_client.rs` (crate `ghost-mls-spike-kat`, the only one with `openmls/test-utils`, for `KeyPackageBundle::new`) injects each vector's KeyPackage and private keys into a fresh `GhostKv`, joins with `JoinBuilder::skip_lifetime_validation()`, then processes every proposal (`store_pending_proposal`, KAT-only) and commit, each call under value semantics (fresh adapter, stored rows, change-set applied on success), and after **every** call runs the reload oracle of §3.4 point 6 (the in-memory group against one reloaded from the rows: epoch, epoch authenticator, tree hash, own leaf, an exporter output). A trial join without `skip_lifetime_validation()` is made on a copy of the rows. Separately, OpenMLS's own KAT tests ran from a shallow checkout at `3a3e35de` (verified `git rev-parse`): `cargo test --locked --release -p openmls --lib --features test-utils,libcrux-provider -- kat read_vectors vectors`.

**Numbers.**
- 148 vectors: 56 welcome, 91 handling-commit, 1 random; suites 0x0001 … 0x0007. The libcrux provider supports 0x0001 and 0x0003 only; **105 vectors (suites 0x0002, 0x0004 … 0x0007) cannot run** with it.
- **All 43 vectors of the provider's suites replay fully**: welcome 8 + 8 (joined, initial epoch authenticator equal), handling-commit 13 + 13 (26/26 epochs each), random 1 (0x0001, 200/200 epochs); **252/252 epoch authenticators equal**, **1 861 reload-oracle checks, all equal**.
- **No clock dependence for commits:** all 1 550 Add KeyPackages in the replayed commits carry the lifetime `[0, u64::MAX]`.
- **Joins:** 42 of the 43 Welcomes are refused without `skip_lifetime_validation()` (expired leaves in their trees); GHOST's join path uses that switch anyway (§19.4 rule 3).
- OpenMLS's own tests at the tag: **371 passed, 0 failed, 6 ignored** (every `read_test_vectors` KAT: passive client, welcome, messages, transcript hashes, key schedule, PSK secret, secret tree, message protection, encryption, tree operations, tree validation, TreeKEM, tree math, crypto basics, deserialisation, storage stability); their parametrised tests ran suite **0x0001 only** — `openmls_test` collapses to the MTI suite unless the `all-ciphersuites` feature is on (`openmls_test/src/lib.rs:8-19`).
- Licence of the vectors: the `mlswg/mls-implementations` repository declares no licence (GitHub licence API: none); the copies are in the MIT-licensed openmls repository. They are test data only and never distributed.

**Verdict: CORRECTS** — in the design's favour. The design expected a clock-dependent subset; the subset is set by the provider's suites, and within it every vector and epoch passes through `GhostKv` with value semantics and the reload oracle.

**Normative correction (S0-13).**
1. §12.2 item (2): replace "runs **only the vectors and epochs whose KeyPackages are valid on the host clock** and reports which (S0 check V10-12)" by "runs every vector of the libcrux provider's suites (0x0001, 0x0003): 43 of the 148 passive-client vectors, 252 epochs (V10-12: all pass through `GhostKv` with value semantics, 1 861 reload-oracle checks). The received Adds carry unbounded lifetimes, so the replay does not depend on the host clock; 42 of the 43 joins need `skip_lifetime_validation()`, which GHOST's join path uses. The 105 vectors of other suites are named as not applicable." §15 item 7 and E-24 follow; "Until V10-12 passes …" is deleted (it passed).
2. §13.2 `mls-vendor-tests.yml`: `cargo test --locked -p openmls --lib --features test-utils,libcrux-provider,all-ciphersuites` (without `all-ciphersuites` the parametrised tests exercise only 0x0001, V10-12); the run at the tag took 55 s of tests.
3. §13.3, the vectors row: "licence: none declared by `mlswg/mls-implementations`; the openmls copies are under MIT; test data, never distributed (V10-12)".

*Effort:* none (the KAT crate is sized in S2). *Owner questions:* none.

---

## 13. V10-13: `refresh_epoch`, `GhostKpBind`, and the AAD round trips

**Question.** Does `GhostLeaf.refresh_epoch` set through `leaf_node_parameters` reach the update-path leaf and read back from the staged commit? Is `GhostKpBind` (0xF0A4) accepted as a KeyPackage extension? Does `set_aad` on commits round-trip through `ProcessedMessage::aad`, and on application messages is `ChannelOrder` readable before decryption through `PrivateMessageIn::aad` and reset after each message?

**Method.** `core/tests/v10_13_ext_aad.rs` over a 3-member world.

**Numbers.**
- `GhostKpBind` (38 B) is accepted; the GHOST KeyPackage is 395 B. A KeyPackage whose leaf capabilities omit 0xF0A4 is **built** by OpenMLS's `KeyPackageBuilder` without complaint and **refused** at the committer's `KeyPackageIn::validate` (`UnsupportedExtension`).
- A self-update with `refresh_epoch = e` through `leaf_node_parameters`: the receiver reads `GhostLeaf` from `StagedCommit::update_path_leaf_node()` and decodes `refresh_epoch = e`.
- `GhostCommitAad` (8 B without evidence) set with `set_aad` round-trips byte for byte through `ProcessedMessage::aad()`; `stage_commit` resets the AAD, and the committer's next message carries none; the AAD is not persisted (a reloaded group has an empty AAD).
- `ChannelOrder` (9 B): read from `MlsMessageIn → PrivateMessageIn::aad()` before decryption together with the header's epoch and content type (`Application`); equal to `ProcessedMessage::aad()` after decryption; the decrypted sender equals `sender_leaf`. `set_aad` applies to exactly the next message: the second `create_message` without `set_aad` carries 0 AAD bytes.

**Verdict: CONFIRMS** all four clauses. No correction; one note for S2: `keyPackage` (§10.2 fn 4) must list 0xF0A4 in the leaf capabilities because OpenMLS's builder does not check it (the design's capabilities row already says so).

---

## 14. V10-14: total nightly occupancy of the existing workflows

**Question.** How much of the four self-hosted runners do the scheduled workflows use per night, measured, before Phase 10 adds `channel-exit-gate`, `channel-privacy-gate`, `channel-state-models`, nightly fuzzing and weekly vendor tests?

**Method.** `scripts/v10-14-nightly.sh 14`: through the GitHub API, every run started by `schedule` in the last 14 days of the eight scheduled workflows (`dm-emulator`, `dm-privacy-gate`, `dm-state-models`, `entitlement-exit-gate`, `messaging-exit-gate`, `monero-regtest`, `signer-timing`, `t2-exit-gate`), and every job's runner, start, end and result (307 jobs). Per night (the UTC date of the run's creation; the crons fire 02:17–04:11 UTC): runner-minutes on `ghost-runner-1 … 4`, the span from the first job start to the last job end, and the longest queue wait (job start − run creation). Jobs on GitHub-hosted runners (before 2026-09-17) are excluded.

**Numbers.**

| Night | jobs | runner-min | span | max queue wait | T2 share | per runner (min) |
|---|---|---|---|---|---|---|
| 2026-09-17 | 25 | 1 218 | 5.5 h | 236 min | 92 % | 283 / 281 / 322 / 332 |
| 2026-09-18 | 25 | 1 111 | 5.1 h | 220 min | 91 % | 301 / 250 / 307 / 252 |
| 2026-09-19 | 25 | 1 295 | 5.8 h | 238 min | 89 % | 351 / 345 / 297 / 302 |
| 2026-09-20 | 18 | 2 331 | **25.0 h** | **1 403 min** | 91 % | 618 / 576 / 535 / 602 |
| 2026-09-21 | 26 | 1 643 | 12.0 h | 835 min | 84 % | 340 / 506 / 470 / 327 |
| 2026-09-22 | 26 | 1 852 | 9.7 h | 425 min | 92 % | 534 / 362 / 534 / 422 |
| 2026-09-23 | 40 | 2 035 | 12.7 h | 689 min | 82 % | 456 / 613 / 439 / 526 |
| 2026-09-24 | 39 | 2 720 | **19.6 h** | **1 122 min** | 75 % | 449 / 890 / 919 / 462 |

- Medians per job (self-hosted): `t2-exit-gate` 134 min (max 240 = its timeout, once), `messaging-exit-gate` 104 (max 481), `signer-timing` 11, `monero-regtest` 14, `entitlement-exit-gate` 10, `dm-state-models` 3.
- Results over the 14 days: `t2-exit-gate` 98 failures / 22 successes, `entitlement-exit-gate` 52 failures / 72 successes / 7 cancelled, `dm-privacy-gate` 22 failures of 22, `dm-emulator` 4 of 4 (`DM-EMULATOR-FAIL: API 29: not run (no report directory …)` — no KVM), `messaging-exit-gate` 1 failure, 1 cancelled.
- **The DM gates fail within 0–2 minutes**, so their designed load — by §13.2's timeouts `dm-privacy-gate` 10 × 300 + 90, `dm-emulator` 2 × 150, `messaging-exit-gate` 480, about 3 900 runner-minutes — is **not in these numbers**. By timeouts, the eight workflows can take ≈ 8 000 runner-minutes a night (≈ 33 h per runner).

**Verdict: CORRECTS.** §13.2 listed the load by timeouts and asked S0 to measure it. Measured: the four runners are busy 4.6–11.3 h each per night with T2 alone taking 75–92 %; on two of eight nights the work spilled over the following day (spans of 19.6 and 25 h, queue waits of 19–23 h), and that is with the DM gates failing at once. Three more nightly gates (one a 60-client, 56-day world with real OpenMLS), nightly fuzzing and weekly vendor tests do not fit; "alternate nights unless the measurement shows room" is not enough — the measurement shows no room.

**Normative correction (S0-14).**
1. §13.2 "Runner budget", after the list of timeouts: "**Measured (V10-14, 8 nights of 2026-09-17 … 24):** 1 111–2 720 runner-minutes per night on the four runners (4.6–11.3 h each), 75–92 % of it `t2-exit-gate`; spans of 5–25 h from first start to last end and queue waits up to 23 h; the DM gates currently fail within two minutes, so their designed ≈ 3 900 runner-minutes are not included. There is no nightly room for Phase 10's gates. Therefore: `channel-exit-gate` and `channel-privacy-gate` run **weekly, on different nights, and on dispatch**; `channel-state-models` (EM-3) runs on pull requests that touch `client-core/mls` or the arbitration code, and weekly; `mls-fuzz` runs **weekly** (one night, 6 h) until capacity exists, and §15 item 8's 'seven nightly runs' becomes 'seven runs'; `mls-vendor-tests` weekly and on pin changes (≈ 15 min). The T2 matrix's share is the owner's decision (Q20)."
2. §12's lesson L-3 and §14's closure blocker (2): "measured in V10-14: the runners are saturated before Phase 10".
3. R-7: likelihood "certain", residue "a green channel gate at the pinned seed count takes weeks, not nights".
4. **Q20 re-asked** with a third point: "The nightly load already fills the four runners (V10-14: up to 2 720 runner-minutes and 25-hour spans a night, T2 75–92 %). Accept weekly channel gates and weekly fuzzing, or rotate T2's ten seed pairs (e.g. two per night) to free room for nightly channel gates?" Default: **weekly channel gates and fuzzing; T2 unchanged** (T2 is Phase 8's gate).

*Effort:* 0.5 day (workflow schedules; S10/S11). *Owner questions:* Q20.

---

## 15. Not run on this host, and why

| Item | Why not here | Where it is closed |
|---|---|---|
| V10-10 on a low-end Android device, and any arm64 execution | no device is attached to this host; the emulator images are x86_64; the arm64 `device_probe` was built but cannot run here | the owner's device step on two arm64 phones (Q20, §12.11), running the S2 successor of `device_probe` |
| Timings that bound anything | the host ran at 100 % CPU (other builds) during every timing; the emulator shares that host | the device step |
| The emulator on API 35 | the `ghost-dm-api35` AVD was in use by another session (emulator-5576) and was not touched; API 29 was used | S12's emulator smoke on the runner or the local fallback |
| KVM runner, CI jobs, staging relays (T1 captures), the external review | not S0's: staging and the review are release gates, CI restoration is Q20; V10-14 reads the CI history instead of running jobs | Q20, §12.12, §15 item 13 |
| OpenMLS's own tests with every suite | the vendor run used the MTI suite (0x0001) because `all-ciphersuites` was off; the passive-client KAT through `GhostKv` covered 0x0003 | `mls-vendor-tests.yml` with `all-ciphersuites` (S0-13) |
| The 105 WG vectors of suites 0x0002, 0x0004 … 0x0007 | the libcrux provider implements none of those suites | not applicable to GHOST (S0-13) |
| A Linux host (JVM worlds, `ghost-dm-host` with MLS) | the spike does not build the host JNI library; the JVM side is S2's | S2 (`ghost-dm-host` exports `MlsNative`) |
| The per-epoch split of S0-6 under crash enumeration and golden upgrade tests | spike code only; measured for size and correctness of reads (the V10-5 runs) | S2 (G-M7 golden, reload oracle, SCN-CH) |

---

## Appendix A. SRLabs report v1.2, re-read (E-25)

The design (Appendix C, E-25) asked S0 to re-read the report rather than rely on summaries. Read in full on 2026-09-25 (`openmls-srlabs` PDF, 41 pages, SHA-256 `791eec15…c38647`, the text extraction of the Phase 9 research):
- **Scope:** OpenMLS crates; the crypto providers "out of scope" (the differential fuzzer covered 46.81 % of the libcrux backend); the PQ suites not covered.
- **Findings:** S3-7 (high, MAC verification accepts truncated/empty tags, mitigated), S2-5, S2-2, S2-6 (medium, mitigated), S1-4 (low, mitigated), **S1-3** (low, *Acknowledged*): state-changing functions are not atomic when the storage provider fails — the report names `merge_pending_commit()`, `commit_to_pending_proposals()`, `process_message()` and `propose_self_update()`; OpenMLS's comment leaves atomicity to the application ("e.g. via a Sqlite transaction"). §3.4's change-set answers it; V10-5 and V10-12 exercised it. **S0-1** (info, *Risk Accepted*): unbounded allocations through a `LeafNodePayload`'s unknown extension, "by creating a KeyPackage **or LeafNode** objects with extremely large unknown extensions" (50 MiB made tree operations take 4.03 s); OpenMLS's comment: applications should check the sizes of incoming payloads. V10-4 showed the LeafNode half of this vector is reachable in GHOST through members' own self-updates within the blob limit; S0-5 closes it by canonical leaves.
- The design's citations of S1-3 and S0-1 (§3.1, §3.7, §6.2.4) are accurate; S0-1's "Risk Accepted" status is confirmed.

---

## Appendix B. Verification re-run (2026-09-25)

After every check had run once, the quick tests were re-run from scratch on the same host (`cargo test --release -p ghost-mls-spike` without the two 100-member populate tests, and `ghost-mls-spike-kat`): **all passed**, and every size of §4 (the 32-member tables, the thresholds, the wide tree, both worst Welcomes, the leaf-inflation series), every V10-11 outcome, the V10-12 totals (252/252) and every V10-13 assertion reproduced byte for byte. The V10-6 determinism outputs were reproduced after a rebuild (identical to the first run). Timings differ between runs as §10 says. The 100-member populated sizes (§4) and the 100-member adapter figures (§5) come from one run each (18.7 min and ≈ 10 min).

**Hygiene.** `cargo fmt --check` clean; `cargo clippy --all-targets -- -D warnings` clean for `ghost-mls-spike` (default, `pq`, `det` with the custom-backend cfg) and `ghost-mls-spike-kat`; `anti-placeholder.sh`, `no-logging.sh` and `dm-jni-surface.sh` green on the tree with the spike present. The probe patch applies cleanly to `d9ff300` (`git apply --check`), and the tree was left with the patch reverted, `ghost/Cargo.lock` restored and `client-core/mls-probe` removed.
