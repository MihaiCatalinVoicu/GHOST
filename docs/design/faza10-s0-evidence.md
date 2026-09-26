# GHOST Phase 10, slice S0: OpenMLS evidence (checks V10-1 … V10-14)

| Field | Value |
|---|---|
| Design | `docs/design/faza10-forum.md` (round 10c, `d9ff300`), §14 row S0 with checks V10-1 … V10-14, and every other place those checks are named (§3.3, §3.4, §3.6, §3.8, §5.4, §5.6, §5.7, §6.8, §10.1, §12.1, §12.2, §13.1, §13.3, §15, §16, §17, §19.4, §19.5, §19.10, §19.11, §19.18, §19.23, Appendix C E-14 … E-25) |
| Scope of this document | all fourteen checks. Run here: V10-1 … V10-9, V10-11 … V10-14 in full; V10-10 on the host and on an x86_64 Android emulator, **not on a low-end device** (§15) |
| Date | 2026-09-25 (first run); 2026-09-26 (review pass: two adversarial reviews, every challenged measurement re-run, Appendix C) |
| Branch | `p10-s0` (worktree of `D:/Forum`), base `d9ff300`; first run committed as `b05fd85` |
| Toolchain | Rust 1.98.1 (`ghost/rust-toolchain.toml`), cargo-ndk 4.1.2, Android NDK 30.0.16248370, cargo-deny 0.20.2, cargo-audit 0.22.2, JDK 17.0.20.1, `gh` (GitHub API) |
| Host | Windows 11 Pro 10.0.26200, Intel Core Ultra 9 275HX (24 cores), 95.4 GiB RAM. **The host was at 100 % CPU during every timing** (other builds share it; sampled before and after): every time in this document is a loaded-host figure, quoted as a **median of repeated runs** where it carries an argument, and bounds nothing |
| Pins measured | `openmls` 0.9.0 (`.crate` SHA-256 `b6b08d90…a8c8`, built from `3a3e35de3feeca8f6605143c464d5452ae584d43` = tag `openmls-v0.9.0`, `.cargo_vcs_info.json`), `openmls_traits` 0.6.0 (`ac13edad…831c`), `openmls_libcrux_crypto` 0.4.0 (`41e6367f…4855`), `openmls_memory_storage` 0.6.0 (`ce927945…5364`), `openmls_serialization_helpers` 0.1.0 (`0e2cf219…84c0`), `hpke-rs` / `-crypto` / `-libcrux` 0.7.0 (`812de62a…b7b1`, `d2c461da…0e24`, `4c1ace95…2613`), `tls_codec` 0.5.0 (`18cc9828…67c8`); every hash equals the `checksum` the resolved lock records |
| Code | `ghost/client-core/mls-spike` (virtual workspace: `ghost-mls-spike`, `ghost-mls-spike-kat`), the temporary patch `ghost/client-core/mls-spike/size-probe/size-probe.patch` and the scripts in `mls-spike/scripts/` |
| Status | Evidence for the lead, **reviewed**. The corrections S0-1 … S0-18 (§0.3) are **folded into `faza10-forum.md`**, listed with where each landed in its §19.26, which wins over its §19.1 … §19.25. |

**How to read.** §0 summarises the verdicts, the values to freeze and the corrections. §1 … §14 are one check each: the question, the method, the numbers, the verdict and the correction with its consequences. §15 lists what could not run on this host and why. Appendix A is the re-read of the SRLabs report the design asked S0 for (E-25); Appendix B the verification re-runs; **Appendix C the review pass** — every finding of the two reviews, its verdict and what changed. Paths are relative to the repository root. `om:` cites `openmls-0.9.0` in the local cargo registry, `ot:` `openmls_traits-0.6.0`. "Blank" means the tree right after one batch add by the owner (only the owner's direct path is set, every other parent blank); "populated" means every parent node set (every member self-updated once); "width" is the tree's leaf count.

---

## 0. Summary

### 0.1 Verdict per check

| Check | Question (short) | Verdict | Correction |
|---|---|---|---|
| V10-1 | graph, licences, cargo-deny, MPL | **CORRECTS** — OpenMLS 0.9.0 does not resolve into the ghost lock with today's pins (a `links = "sqlite3"` conflict through its *optional* `openmls_sqlite_storage`); a stub resolves it (+40 lock entries, 22 names linked), and so does pinning `libsqlite3-sys` back to 0.35 (Arti 0.46 allows it; SQLite 3.50.2); no strong copyleft (three MPL-2.0 crates, file-level); cargo-deny green | S0-1 |
| V10-2 | advisories at the pins | **CORRECTS** — nothing open at the pins, but §3.7's list was incomplete, OpenMLS's advisories are **not in RustSec**, and two libcrux entries are filed under a former crate name, so cargo-deny/cargo-audit cannot see them | S0-2 |
| V10-3 | size in `libghost_client_net.so` | **CONFIRMS** the budget from the committed tree: +2 488 200 B (arm64-v8a), +2 916 384 B (x86_64); x86_64 keeps only 7.3 % headroom; T12's same-path identity holds for the grown library | S0-3 |
| V10-4 | commit/Welcome sizes at the caps, composite worst cases | **CORRECTS** — with a canonical KeyPackage every single-proposal commit fits both floors in every reachable width (tightest: 172 B, a restore swap at 32 members in a 128-leaf tree); with §6.2.4's 1 024 B bound an Add exceeds C(4096) from 27 members (26 at 128 leaves); leaf inflation makes 100-member Welcomes unsendable; §5.7's deferral order can strand a Remove from the drop of its key | S0-4, S0-5, S0-16 |
| V10-5 | adapter cost | **CORRECTS** — 53 storage methods, not 72; OpenMLS rewrites all retained past epochs on every post (up to 1.19 MB at 32 and 3.41 MB at 100 members per post); the split into rows fixes the I/O, not the CPU; per-call costs as medians; batched calls | S0-6, S0-17 |
| V10-6 | determinism | **CONFIRMS** the process-global stream (two processes byte-identical) with three stated preconditions | S0-7 |
| V10-7 | portable libcrux | **CONFIRMS** §19.23 (`libcrux-aes` stale cfg reproduced; portable builds verified from build outputs and symbols); S0 decides: extract the script | S0-8 |
| V10-8 | bootstrap in the Welcome's GroupInfo | **CORRECTS** (first run: confirms) — the bootstrap reaches the GroupInfo and a corrupted GroupInfo signature is refused, so the fallback is not needed; **but that signature authenticates only a signer the Welcome's own tree supplies**: a holder of the join key can build a group under the channel's id and Welcome the joiner, OpenMLS accepts it, and an applied forgery consumes the KeyPackage (measured); a committers anchor refuses it | S0-9, S0-15 |
| V10-9 | 0x004D/0x004F with libcrux (Q2 evidence) | **CONFIRMS** D3 with corrected numbers (all three code points run end to end — one implementation with itself, all mapped to one X-Wing KEM; 28.8–48.9 KB commits at 20–32 members) | S0-10 |
| V10-10 | host timings; low-end device | **INCONCLUSIVE** for devices (none available); host medians and x86_64-emulator figures recorded; retention multiplies call times | S0-11 |
| V10-11 | OpenMLS's wall-clock sites | **CORRECTS** — the world range holds, but a lifetime refusal masks other defects of the same commit, so "lifetime-pending, ranked as valid" is unsound, and a rule that consults the trusted day only when OpenMLS refused still lets a committer split members; OpenMLS never checks the lifetime span | S0-12 |
| V10-12 | passive-client replay through GhostKv | **CORRECTS** (in the design's favour, with limits) — every vector of the provider's suites replays (43 vectors, 252/252 epochs, 1 861 reload checks of the fingerprint half); the subset is set by suites, not by the clock; suite 0x0003 is only 21 vectors / 26 epochs; the replay tests the adapter, not GHOST's join path | S0-13 |
| V10-13 | `refresh_epoch`, `GhostKpBind`, AAD round trips | **CONFIRMS** | — |
| V10-14 | nightly occupancy | **CORRECTS** — measured by trigger: on development days the four runners are 87–97 % busy, 54–67 % with push-triggered gates, and scheduled runs start 4.6–5.7 h after their crons (the owner's morning); channel gates cannot be nightly | S0-14 |

### 0.2 Values to freeze

| Constant | Value | Evidence |
|---|---|---|
| GHOST KeyPackage (MlsMessage, canonical form) | **395 B**, every day (lifetime, `GhostLeaf` 41 B, `GhostKpBind` 38 B, the canonical capabilities) | V10-4, V10-13 |
| Largest single-proposal commit, small cap (32 members, canonical KeyPackage) | restore swap **3 786 B** at 32 leaves, 3 821 at 64, **3 856 B at 128 leaves (margin 172 B)**; Add 31 → 32: 3 745 / 3 780 / 3 815 (margin 213) | V10-4 |
| Largest single-proposal commit, large cap (100 members, blank, 128 leaves) | restore swap 9 432 B canonical (margin 6 884); Add 99 → 100: 9 391 B canonical, 10 020 B with a 1 024 B KeyPackage | V10-4 |
| Welcome for one joiner (canonical leaves) | 8 818–9 111 B at 32 (blank, 32–128 leaves; 10.8–10.9 KB populated), 16 KiB bucket; 25 894–26 523 B at 100 (blank; 33.6–33.7 KB populated), 64 KiB bucket | V10-4 |
| Largest text post (16 000 B text, `ChannelOrder`) | 16 198 B, margin 118 to C(16384) (98 with `reply_to`) | V10-4 |
| Library delta (stripped, committed tree `b05fd85`) | +2 488 200 B arm64-v8a, +2 916 384 B x86_64; PQ feature +16 792 / +37 040 B more | V10-3 |
| `MessageSecrets` growth per retained past epoch | ≈ 18.5 KB (32 members), ≈ 53 KB (100) | V10-5 |
| StorageProvider methods in the P0 feature set | 53 (41 group-scoped, 12 global) + `version()` | V10-5 |
| Runner load (4 self-hosted runners, 2026-09-17 … 25) | days without pushes 19–21 %, development days 87–97 % (54–67 % of it push-triggered); scheduled runs created 275–340 min after their crons | V10-14 |

### 0.3 Normative corrections (folded into `faza10-forum.md`, §19.26)

| # | Check | Correction (short) |
|---|---|---|
| S0-1 | V10-1 | lock resolution: a manifest-only stub for `openmls_sqlite_storage` (default) or `libsqlite3-sys` 0.35 with SQLite 3.50.2 (Q40); G-M1's 22 names; the stub under GHOST's own licence; the KAT crate as a workspace member adds 13 test-only packages; notice texts from the upstream repository |
| S0-2 | V10-2 | the complete advisory list; a GHSA watch over `openmls/openmls`, `celabshq/hpke-rs`, `celabshq/libcrux` and RustSec by former crate names |
| S0-3 | V10-3 | measured size from the committed tree; budget enforced per ABI; S2's exit re-measures with the real crate |
| S0-4 | V10-4 | the canonical KeyPackage (one definition, 395 B golden) replaces "≤ 1 024 bytes"; §5.7's table replaced by the measured one (32, 64, 128 leaves; 100 members); golden sizes in G-M7; Q3 re-asked with both options |
| S0-5 | V10-4 | every leaf a commit installs is canonical (CO-2): four inflated self-updates otherwise lock joins out of a 100-member channel; SRLabs S0-1 closed by that rule, not by the 64 KiB blob |
| S0-6 | V10-5 | 53 methods; per-epoch rows for past epochs; `max_past_epochs` 64 → 16 and every literal that follows; `mls_kv` not WITHOUT ROWID; R-3 and Q18 with medians |
| S0-7 | V10-6 | the preconditions of byte-identical runs: one rayon worker, the `added_at` day rewrite, one getrandom major in the host library's linked graph (`-e normal,no-proc-macro`) |
| S0-8 | V10-7 | `ghost/scripts/gates/libcrux-portable.sh` extracted, generic over the four packages |
| S0-9 | V10-8 | the bootstrap travels only in the GroupInfo; `K_boot` and `boot_flag` withdrawn; `create_group_info(false)` on every commit; the V10-8 tests move to S2 |
| S0-10 | V10-9 | measured PQ sizes; the three code points share one KEM and the provider does not check it |
| S0-11 | V10-10 | host (medians) and emulator figures; the retention effect; the device step runs the S2 successor of `device_probe`, at S2's exit if a phone is available |
| S0-12 | V10-11 | one trusted-day lifetime predicate on both branches of OpenMLS's answer; `clock_blocked` only while the trusted day accepts; CO-2 (A) checks the lifetime form; the malicious-committer split declared; monotonic `commit_minute` declined |
| S0-13 | V10-12 | the replayed subset is the provider's suites (43 of 148 vectors, 252 epochs); what the replay proves and does not; `all-ciphersuites` in the vendor tests; the vectors' licence; Q22 re-asked |
| S0-14 | V10-14 | channel gates on dispatch and weekly, never on push; fuzzing by target-hours; Q20 re-asked with options on the existing push triggers |
| S0-15 | V10-8 (review) | the committers anchor: invite and `INVITE_ISSUED` carry a digest of the committers; the joiner accepts only a Welcome signed by one of them (a rejoiner: its last committers); a refused Welcome writes nothing; an admitting commit leaves `committers` unchanged; a change of committers voids outstanding invites (Q41) |
| S0-16 | V10-4 (review) | §5.7's deferral order keeps a Remove with the drop of its key and defers swaps before the context change |
| S0-17 | V10-5 (review) | batched calls under value semantics (`receive` of up to 32 messages, `trialCount`), per-item rollback, a cache seam |
| S0-18 | S0 exit (review) | the obligations outside the §14 row: R-8's re-run of the Phase 9 suites, the G-R/G-M pairs built once generically, seed and mutant counts pinned at S10/S11, Appendix C statuses, §17 frozen or re-asked, the effort restated |

**Effort** (F9 pace, the unit of §14): S2 +3.25 d (S0-1 0.25, S0-2 0.25, S0-3 0.25, S0-6 1, S0-7 0.25, S0-8 0.5, S0-11 0.25, S0-17 0.5), S4 +0.75 (S0-5 0.25, S0-15 0.5, S0-17 0.25, S0-9 −0.25), S5 +1.75 (S0-5 0.25, S0-12 0.75, S0-15 0.25, S0-16 0.25, S0-17 0.25), S10 and S11 +0.25 each (S0-14): **+6.25 working days**, §14's total 34.5 → **40.75**.

**Owner questions raised or re-asked.** **Q40 (new)**: the stub or the older SQLite (default: stub). **Q41 (new)**: the committers anchor and its costs (default: anchor). **Re-asked:** Q3 (canonical KeyPackages at 32, or 1 024 B KeyPackages at 26; default canonical), Q16 (the unused KEM code; default accept), Q18 (value semantics with per-epoch rows, cap 16 and batched calls, or a native cache now; default value semantics), Q20 (the push triggers of the existing gates; default: channel gates on dispatch and weekly, the owner decides the rest), Q22 (0x0003's thin WG coverage; default no differential peer), Q26 (one actor; default yes with batched calls). Q2 keeps its default with measured sizes. All other questions are frozen with their defaults.

### 0.4 The spike

`ghost/client-core/mls-spike` is **not a member of the ghost workspace**: it is a virtual workspace with its own `Cargo.lock` (the `dm-spike` precedent: `ghost/Cargo.toml` simply does not list it), so the product lock, `rust-dependency-allowlist.txt`, the crypto pins and the ghost `cargo deny` are untouched. Its `core/src` passes `anti-placeholder.sh`, `no-logging.sh` and `dm-jni-surface.sh` (run on the tree with the spike present); `cargo fmt --check` and `cargo clippy --all-targets -D warnings` are clean for `ghost-mls-spike` (default, `pq`, `det`) and `ghost-mls-spike-kat`. **Since the review pass its tests assert the numbers this document quotes** (golden sizes, outcomes, replay totals; only V10-10's timings, which bound nothing, are printed without assertion). The README (`ghost/client-core/mls-spike/README.md`) gives every command. **Fate:** deleted when `ghost-client-mls` and `ghost-client-mls-kat` land in S2; nothing in it is a production source.

---

## 1. V10-1: dependency graph, licences, cargo-deny, MPL

**Question.** Which packages does OpenMLS 0.9.0 with the libcrux provider add to the shipped graph of `libghost_client_net.so` on both Android triples, under which licences, and do `cargo deny` and the licence rules of ADR-37 stay green?

**Method.** The patch `size-probe/size-probe.patch` adds a temporary crate `ghost-mls-probe` (the spike's `GhostKv`, provider, extensions and harness compiled by `#[path]`, so it makes every call `ghost-client-mls` will make) to the ghost workspace and to `ghost-client-net` behind the features `mls-probe` and `mls-probe-pq`. The lock was resolved `--offline` against the existing `ghost/Cargo.lock`. Then `cargo tree --offline -p ghost-client-net -e normal --target {aarch64,x86_64}-linux-android` with and without the features, `-e normal,no-proc-macro` for what is linked, licences read from each package's `Cargo.toml` in the registry, a scan of every added crate's sources for GNU licence text, SPDX identifiers and "Signal Messenger" copyrights, and `cargo deny --offline check` with `ghost/deny.toml`. **Review pass:** the same in scratch copies of the committed tree (never the worktree) for the two alternatives below.

**Result 1 — the lock does not resolve with today's pins.** With `openmls = "=0.9.0"` in the workspace, `cargo metadata --offline` fails:

```
error: failed to select a version for `libsqlite3-sys`.
    ... required by package `rusqlite v0.37.0`
    ... which satisfies dependency `rusqlite = "^0.37"` of package `openmls_sqlite_storage v0.3.0`
    ... which satisfies dependency `openmls_sqlite_storage = "^0.3.0"` of package `openmls v0.9.0`
package `libsqlite3-sys` links to the native library `sqlite3`, but it conflicts with a previous package which links to `sqlite3` as well:
package `libsqlite3-sys v0.37.0`
    ... which satisfies dependency `libsqlite3-sys = "^0.37.0"` of package `ghost-client-net v0.1.0`
```

`openmls_sqlite_storage` is an **optional** dependency of `openmls` (feature `sqlite-provider`, forbidden by §3.2), but Cargo resolves the lock for every feature, and `links` values must be unique in the whole resolve. The ghost lock has `rusqlite 0.39.0` → `libsqlite3-sys 0.37.0` (Arti's directory cache; bundled SQLite 3.51.3); `openmls_sqlite_storage 0.3.0` requires `rusqlite ^0.37` → `libsqlite3-sys ^0.35`. There is no newer `openmls_sqlite_storage` (crates.io: 0.3.0 of 2026-08-25 is the newest; its `rusqlite` requirement is `^0.37`), and upstream `main` (`0cf0b0d`, 2026-09-24) still pins `rusqlite = "0.37"`. The research probes never met this because they built in their own workspaces without Arti.

**Two ways out, both measured.**
- **(a) A stub (the default of Q40).** A stand-in crate with the same name and version and no dependencies (`openmls_sqlite_storage` 0.3.0, empty `lib.rs`, the four feature names `openmls` forwards to it declared empty), wired in by `[patch.crates-io]`, lets the lock resolve: **+40 lock entries** (plus the probe crate itself), of which 22 are linked (below); the other 18 are optional graph members that nothing enables (`openmls_rust_crypto`, `openmls_basic_credential`, `openmls_test`, `hpke-rs-rust-crypto`, `k256`, `ml-dsa`, `aes`, `aes-gcm`, `ctr`, `ghash`, `polyval`, `universal-hash`, `chacha20 0.9.1`, `chacha20poly1305 0.10.1`, `poly1305 0.8.0`, `aead 0.5.2`, `opaque-debug`, the stub). Because the sqlite feature is forbidden, the stub is never compiled into any graph. The probe declared it `MIT`; in the product it is GHOST's own crate (`LicenseRef-GHOST-Proprietary`, `publish = false`).
- **(b) An older SQLite (the alternative of Q40; review finding H2).** Arti 0.46's `tor-dirmgr` requires `rusqlite = ">=0.36.0, <0.40.0"` (`tor-dirmgr-0.46.0/Cargo.toml`), so pinning **Arti's** rusqlite back is allowed. Without the stub and with `ghost-client-net`'s `libsqlite3-sys` changed from 0.37.0 to 0.35.0, `cargo metadata --offline` resolves: rusqlite 0.39.0 → 0.37.0, libsqlite3-sys 0.37.0 → 0.35.0 (bundled SQLite **3.51.3 → 3.50.2**, read from each crate's `sqlite3.h`), hashlink 0.11.1 → 0.10.0; `foldhash` 0.2.0, `rsqlite-vfs` 0.1.1 and `sqlite-wasm-rs` 0.5.5 leave the lock, and the real `openmls_sqlite_storage` enters it with `refinery` 0.9.2, `refinery-core` and `refinery-macros` (optional, never compiled). SQLite 3.50.2 carries CVE-2025-7709 (an FTS5 defect that needs control of the database file, fixed in 3.50.3; sqlite.org/cves.html, 2026-09-26). The first run's Q40 text said Arti 0.46 "does not allow" this: **it was wrong**.

**Result 2 — the graph (with the stub).**

| | arm64-v8a | x86_64 |
|---|---|---|
| package names, baseline → with the MLS stack | 417 → 439 | 418 → 440 |
| name+version pairs | 461 → 483 | 462 → 484 |
| names added (identical on both triples) | 22 | 22 |
| new versions of names already present | 0 | 0 |
| added by `mls-probe-pq` over `mls-probe` | 0 | 0 |

The 22 names, with versions and declared licences: `openmls` 0.9.0, `openmls_traits` 0.6.0, `openmls_libcrux_crypto` 0.4.0, `openmls_memory_storage` 0.6.0, `openmls_serialization_helpers` 0.1.0 (MIT); `hpke-rs`, `hpke-rs-crypto`, `hpke-rs-libcrux` 0.7.0 (**MPL-2.0**); `libcrux-aead` 0.0.9, `libcrux-aes` 0.0.9, `libcrux-chacha20poly1305` 0.0.9, `libcrux-ed25519` 0.0.9, `libcrux-hkdf` 0.0.8, `libcrux-hmac` 0.0.8, `libcrux-hmac-drbg` 0.0.1, `libcrux-poly1305` 0.0.6 (Apache-2.0); `rayon` 1.12.0, `rayon-core` 1.13.0, `crossbeam-deque` 0.8.8, `crossbeam-epoch` 0.9.21 (MIT OR Apache-2.0); `tls_codec` 0.5.0, `tls_codec_derive` 0.5.0 (Apache-2.0 OR MIT). `tls_codec_derive` and `openmls_serialization_helpers` are proc-macro/build-time only: the linked set (`-e normal,no-proc-macro`) is the other 20 (358 → 378 linked names). `libcrux-sha2`, `libcrux-kem`, `libcrux-ml-kem`, `crossbeam-utils` and `either` are already in the baseline graph (the DM stack and Arti), so §13.1's G-M1 list ("… `crossbeam-utils`, `either`, … minus names already present") is exact once those are removed.

**The KAT crate as a workspace member (review finding I10).** A member shaped like `ghost-client-mls-kat` (`openmls` with `test-utils` as a dev-dependency, the `dm-host` precedent) adds **13 more packages** to the lock over the stub layout: `addr2line`, `backtrace`, `cast`, `gimli`, `minicov`, `miniz_oxide`, `object`, `oorandom`, `rustc-demangle`, `wasm-bindgen-futures`, `wasm-bindgen-test`, `wasm-bindgen-test-macro`, `wasm-bindgen-test-shared` (53 in all). Offline resolution stops at `addr2line 0.25.1`, which was not cached; resolved online (crates.io only), `cargo deny --offline check` is **advisories ok, bans ok, licenses ok, sources ok**. None of the 13 is in a shipped or host graph.

**Licence facts.** No added source file contains GNU licence text, a GNU SPDX identifier, an MPL header or a "Signal Messenger" copyright (scan of all 566 `.rs` files of the 22 crates). **No strong copyleft**: the three `hpke-rs` crates are MPL-2.0, a file-level copyleft that ADR-37 point 2 allows unmodified with the source offered. **None of the OpenMLS, hpke-rs or libcrux `.crate` archives ships a LICENSE file** (only `rayon*`, `crossbeam*`, `tls_codec*` do): the notices generator must take the MIT text with the upstream copyright line "Copyright (c) 2020 OpenMLS Authors" (repository `LICENSE` at `3a3e35de`, read) and the MPL-2.0 and Apache-2.0 texts from the SPDX snapshot, as Phase 9 did for libcrux.

**cargo-deny** on the patched workspace (`all-features = true` as `deny.toml` sets it): **advisories ok, bans ok, licenses ok, sources ok** with the cached database of 2026-09-22 and with a fresh one (V10-2). MPL-2.0 is on the allow list; the path source of the stub does not trip `sources`.

**Verdict: CORRECTS.** The design's graph and licence claims hold, but the stack cannot enter the workspace as §3.2 wrote it, and there are two ways to make it enter.

**Correction S0-1 (folded: D2, §3.2, §3.9, §10.1, §13.1 G-M1/G-M2, §13.3, §17 Q40, §18 F-5, ADR-40).** §3.2's lock-resolution rule with the stub as the default and the older SQLite as Q40's alternative; G-M2 checks that the stub is never compiled and holds only an empty `lib.rs`; G-M1 names the 22 packages; §13.3's stub row (GHOST's licence) and "not added: the real `openmls_sqlite_storage`"; §10.1 records the KAT crate's 13 test-only packages; F-5 gains the upstream request. *Effort:* 0.25 day in S2. *Consequences:* none on formats or protocol.

---

## 2. V10-2: advisories at the pins

**Question.** Is any advisory open against the pinned OpenMLS stack, and does the project's advisory tooling see them?

**Method.** (1) `cargo audit` 0.22.2 with a fresh clone of `rustsec/advisory-db` (commit `593df8c1`, 2026-09-24 16:38 +0200) into the scratchpad (`--db … --no-fetch`), on the patched `ghost/Cargo.lock` and on the unpatched one. (2) `cargo deny check advisories` with a copy of `ghost/deny.toml` whose `db-path` pointed at the same fresh database. (3) Every RustSec entry for a crate of the stack — **including the provider crates already in the baseline** (review finding H11) — read. (4) GitHub repository advisories of `openmls/openmls`, `hpke-rs` and `libcrux` through the API. Review pass: the RustSec repository at `e2111519` (2026-09-25 17:51 UTC) through the API, and the advisories API again on 2026-09-26.

**Numbers.**
- `cargo audit`, patched vs unpatched lock: **identical findings** — `rsa` 0.9.10 and 0.10.0-rc.18 (RUSTSEC-2023-0071), `bincode` (RUSTSEC-2025-0141), `paste` (RUSTSEC-2024-0436), `proc-macro-error2` (RUSTSEC-2026-0173); all pre-existing, all in `deny.toml`'s reviewed list or unmaintained-only. The MLS stack adds none.
- `cargo deny check advisories` with the fresh database: **advisories ok**.
- **Every RustSec entry for a crate the stack links, all fixed at the locked versions:** `hpke-rs` RUSTSEC-2026-0069/0070/0071 (aliases GHSA-g433-pq76-6cmf; patched ≥ 0.6.0; pin 0.7.0); `libcrux-ed25519` RUSTSEC-2026-0026 (GHSA-435g-fcv3-8j26, CVE-2026-76234; ≥ 0.0.6) and RUSTSEC-2026-0075 (GHSA-434v-x5qv-pmh6, "all-zero key generation on catastrophic RNG failure"; ≥ 0.0.7; pin 0.0.9); **`libcrux-ecdh` RUSTSEC-2026-0023** (GHSA-435g-fcv3-8j26: "X25519 secret validation did not check buffer length or clamping", the key exchange of suite 0x0003; ≥ 0.0.6; locked 0.0.8); `libcrux-chacha20poly1305` RUSTSEC-2026-0124 (GHSA-hc3c-63hc-2r9f; ≥ 0.0.8; pin 0.0.9); `libcrux-poly1305` RUSTSEC-2026-0073 (GHSA-pv9v-5j35-xwcr; ≥ 0.0.5; pin 0.0.6); **`libcrux-sha3`** RUSTSEC-2026-0074 (≥ 0.0.8), **-0207 and -0208** (≥ 0.0.10; locked 0.0.10); **`libcrux-secrets` RUSTSEC-2026-0212** (≥ 0.0.6; locked 0.0.6); **`libcrux-intrinsics` RUSTSEC-2025-0133** (≥ 0.0.4; locked 0.0.8); **RUSTSEC-2026-0209 and -0211**, AES-GCM AAD limits and a non-constant-time tag check, filed under **`libcrux-aesgcm`, the former name of `libcrux-aes`**, with `patched = []` and the text "starting from version 0.0.9 (published as `libcrux-aes@v0.0.9`)" — fixed in the pinned `libcrux-aes` 0.0.9, but invisible to cargo-deny and cargo-audit, which match package names; `crossbeam-epoch` RUSTSEC-2026-0204 (≥ 0.9.20; pin 0.9.21); `crossbeam-deque` RUSTSEC-2021-0093 and `crossbeam-utils` RUSTSEC-2022-0041 (old, fixed).
- **RustSec has no entry for `openmls` at all** (no `crates/openmls` directory at `593df8c1` nor at `e2111519`). GitHub lists four OpenMLS advisories: GHSA-w62v-gv48-63rh (medium, 2026-08-25, quadratic duplicate detection, `< 0.9.0`), GHSA-rrmv-c79f-cf5r (medium, 2026-08-25, out-of-bounds panic in manual `DeserializeBytes`, `< 0.9.0`), GHSA-8x3w-qj7j-gqhf (high, 2026-02-04, improper tag validation, `< 0.7.2`), GHSA-qr9h-x63w-vqfm (medium, 2025-09-26, secret tree not persisted, `0.7.0` → `0.7.1`). **The hpke-rs and libcrux repositories moved to `celabshq/`** (`cryspen/*` redirects): `celabshq/hpke-rs` lists GHSA-g433-pq76-6cmf; `celabshq/libcrux` lists GHSA-435g-fcv3-8j26 ("Bug-Fixes in `libcrux-ecdh`, `libcrux-ed25519`, `libcrux-psq`"); the other libcrux GHSA ids above appear only as RustSec aliases.

**Verdict: CORRECTS.** Nothing is open at the pins (the design's conclusion stands), but (a) §3.7's advisory column named two provider-side advisories where the database holds sixteen entries on crates the stack links, and (b) the design's advisory watch ("`cargo deny` green", G-M1) is blind to OpenMLS itself (none of its four advisories reached RustSec) and to entries filed under a crate's former name.

**Correction S0-2 (folded: §3.1, §3.7, §13.1 G-M1, §13.2, R-6, §18 F-5, F-11, E-4).** §3.7's cell lists every entry above; G-M1 and `mls-vendor-tests.yml` (weekly and on pin changes) query `repos/{openmls/openmls, celabshq/hpke-rs, celabshq/libcrux}/security-advisories` and RustSec by package **and former package names**, failing when an advisory's vulnerable range contains a pinned version; R-6's mitigation gains the GHSA watch; F-11 asks RustSec to map the `libcrux-aesgcm` entries. *Effort:* 0.25 day (S2).

---

## 3. V10-3: size of the OpenMLS stack in `libghost_client_net.so`

**Question.** What does the stack cost in the shipped library, measured the way `scripts/build-native.sh` builds it, and what is linked?

**Method.** `scripts/v10-03-size-build.sh` builds `ghost-client-net` for arm64-v8a and x86_64 as `build-native.sh` does (cargo-ndk 4.1.2, release, `strip = "symbols"`, the same path remapping, the workspace's portable-libcrux `[env]`, the libcrux packages cleaned per triple before each build), `--offline` instead of `--locked` because the patch changes the lock. Variants: the unpatched tree; the probe linked with its JNI export only; `mls-probe`; `mls-probe-pq`; and unstripped builds (`--config profile.release.strip=false`) of the baseline and of `mls-probe` for the symbol analysis (`scripts/v10-03-symbols.sh`: `llvm-nm -C -S --defined-only` from NDK 30, sizes summed by the first path segment of each demangled symbol — approximate, since generic instantiations land under `core`, `alloc` or the caller). **Review pass (finding H5):** the first run's probe builds compiled spike sources (`ext.rs`, `harness.rs`) that were edited after the builds, so its bytes did not reproduce from the committed tree; every variant was rebuilt from `b05fd85` in a scratch copy (`git archive`), in a fresh target directory, and T12 was checked by building `mls-probe` again in a second fresh target directory at the same source path.

**Numbers (bytes; committed tree `b05fd85`).**

| Variant | arm64-v8a | Δ vs baseline | x86_64 | Δ vs baseline |
|---|---|---|---|---|
| baseline (`main` at `d9ff300`) | 17 931 600 | — | 19 519 400 | — |
| probe linked, no MLS (new lock) | 17 926 920 | −4 680 | 19 519 368 | −32 |
| **OpenMLS 0.9.0 + libcrux provider + GhostKv + GHOST calls** | **20 419 800** | **+2 488 200** | **22 435 784** | **+2 916 384** |
| same with `draft-ietf-mls-pq-ciphersuites` | 20 436 592 | +2 504 992 | 22 472 824 | +2 953 424 |
| unstripped: baseline / MLS | 31 965 936 / 35 707 456 | +3 741 520 | 31 430 352 / 35 319 152 | +3 888 800 |

(The first run's MLS row, built from the edited sources, was 20 417 984 / 22 438 568, +2 486 384 / +2 919 168; its PQ row 20 434 880 / 22 469 208. The baseline and no-MLS rows reproduce byte for byte.)

- The budget of §3.8 (≤ +3 MiB = 3 145 728 B per ABI) holds: 2.37 MiB and 2.78 MiB. **x86_64 keeps only 229 344 B (7.3 %) of headroom**, and the probe lacks most of `ghost-client-mls`'s own code (the JNI functions, the seal, the codecs, the reveal): the budget must be enforced per ABI and re-measured with the real crate at S2's exit. The research probe's +2.68–2.88 MB / +3.27–3.32 MB over-estimated (it shared less with the baseline).
- **T12 (reproducibility):** the `mls-probe` variant rebuilt at the same source path in a **fresh** target directory (a full build of both triples, 5 min 23 s) is **byte-identical** to the first build on both ABIs (SHA-256 `38c2f815…08e2` arm64-v8a, `87d204a0…d790` x86_64), so T12's same-path identity and `native-libs.sha256` cover the grown library. A different source path was not tried; T12 does not ask for it.
- Symbol-size attribution of the delta (`v10-03-symbols.sh`, regenerable; arm64-v8a, x86_64 in parentheses; net +2 094 035 (+2 460 041) B of symbols): `openmls` 529 KB (608), `serde_json` 355 KB (396: OpenMLS's serde entities through `GhostKv`'s JSON and the day rewrite), `libcrux_ml_kem` 296 KB (339), `core` 253 KB (263), `alloc` 135 KB (171), `libcrux_p256` 119 KB (186), the probe's own code 98 KB (134), `libcrux_ed25519` 36 KB (46), `hashbrown` 30 KB (33), `libcrux_sha2` 26 KB (34), `rayon_core` 24 KB (27), `hpke_rs` 16 KB (20), `libcrux_aes` 16 KB (20), `libcrux_hkdf` 15 KB (20), `libcrux_chacha20poly1305` 12 KB (13), `tls_codec` 12 KB (12), `libcrux_kem` 10 KB (12). (The first run quoted the arm64 figures of an earlier, buggier aggregation that its saved files did not regenerate; the review nit is closed by the committed script.)
- **Linked but unused by suite 0x0003:** `libcrux_p256` and `libcrux_ecdh`'s P-256 path, and ML-KEM-512/1024 (`mlkem512`, `mlkem1024` symbols present, 12 of them on arm64; the baseline's DM stack links only ML-KEM-768 through the slice trait, F9 V-9): `hpke-rs-libcrux` dispatches over every KEM at run time. Together ≈ 0.42 MB (arm64) / 0.53 MB (x86_64) of the delta. Removing it would need a GHOST-written `OpenMlsCrypto` (the alternative of Q16), which is not proposed: the budget holds.
- **Dropped by the linker:** no symbol of `openmls_memory_storage`, of `openmls_libcrux_crypto::Provider`, of `test_utils` or of `fork_resolution` (0 matches on both ABIs); `skip_validation` has 3 symbols (the flag readers, never set).
- **Exports:** the only new dynamic symbol is the probe's `Java_org_ghost_crypto_bridge_MlsNative_probeMls`; the library exports 52 dynamic symbols against the baseline's 51, on both ABIs.

**Verdict: CONFIRMS** (budget), with the committed tree's numbers replacing the first run's.

**Correction S0-3 (folded: §3.8, §13.2 `android-native`, §14 S2 exit, §15 item 9, R-4, Q16, ADR-40, E-15).** §3.8 records the measured delta, the unused KEM code, the dropped memory provider and the per-ABI budget; S2's exit re-measures with the real crate by this method and fails above the budget on either ABI; R-4 becomes "certain / low on arm64-v8a, medium on x86_64"; ADR-40's consequences carry the measured figure. *Effort:* 0.25 day (S2).

---

## 4. V10-4: commit and Welcome sizes with GHOST's extensions at the class caps

**Question.** Do commits with GHOST's extensions (`GhostLeaf` in every update-path leaf, `GhostCommitAad` with evidence of the right size, proposals by value, the forced path of §6.8) fit `C(4096) = 4 028` at 32 members and `C(16384) = 16 316` at 100, including §5.7's composite worst cases "in a maximally blank tree with unmerged leaves"? What do Welcomes need? If a single-proposal commit exceeds the small floor, what is the largest small class that fits?

**Method.** `core/tests/v10_04_sizes.rs` over the spike harness: real OpenMLS 0.9.0, suite 0x0003, GHOST's configuration (§3.5: `padding_size 0`, ratchet tree in the Welcome, sender ratchet (16, 1000), `max_past_epochs 64`, `RequiredCapabilities` naming 0xF0A1 and 0xF0A2, `GhostChannelContext` in the context), GHOST KeyPackages (day-aligned 84-day lifetime, `GhostLeaf`, `GhostKpBind`, capabilities 0x0003 / 0xF0A1, 0xF0A2, 0xF0A4 / Basic), every commit with `force_self_update(true)` and a `GhostLeaf` update leaf with `refresh_epoch`, and `GhostCommitAad` carrying `AdmitEvidence` (245 B) or `SwapEvidence` (rejoin 146 B, restore 279 B). Each probe commit is built by a member, validated by another member (`process_message`, change-set discarded) and dropped. Shapes: **blank** (one batch add by the owner — the owner's copath resolution then covers all n−1 other leaves, the maximal number of path ciphertexts), **populated**, **wide** and **random histories** (60 steps of self-updates, removals by the owner and re-adds by the owner or rank 1 at 26–32 members, probing the owner's and the far member's commits every 5 steps). KeyPackages are GHOST-shaped (395 B) or inflated with extra capability extension types to §6.2.4's bound of 1 024 B. Sizes are `MlsMessageOut` bytes, the seal's body. **Since the review pass the test asserts the golden sizes quoted here.**

**Wide trees (review finding H3).** A 32-member channel's tree is 32 leaves wide unless it once held more members: a large channel shrunk to 32 members and switched to the small class (which §5.3 allows) keeps a 64- or 128-leaf tree while its rightmost leaf is occupied, and 128 leaves is the widest a class-capped channel can be (Adds fill the leftmost blank leaf, so no leaf index reaches 100 while the large cap holds). **The first run's "wide (64 leaves)" column was wrong**: its probes removed leaf 32, the only member in the right half, so OpenMLS truncated the tree back to 32 leaves and the Remove, swaps and composite equalled the blank values. The review pass builds 64- and 128-leaf trees by a batch add of 33 or 65 members and one batch removal that keeps every copath subtree of the owner non-empty (so its update path has the tree's full depth, 5, 6 or 7 nodes), and never removes or swaps the rightmost occupied leaf. Each extra level adds one update-path node: **+35 B**.

**Numbers — small class, 32 members (bytes; margin to C(4096) = 4 028).**

| Commit | Blank, 32 leaves | 64 leaves | **128 leaves** | Populated |
|---|---|---|---|---|
| empty self-update, rank 255 | 1 955 | 2 072 | 1 990 | 1 053 |
| owner's PCS commit (empty, with path) | 3 185 | 3 220 | 3 255 | 1 053 |
| Remove 1 | 3 110 | 3 145 | 3 180 | 1 306 |
| swap with rejoin evidence | 3 653 | 3 688 | 3 723 | 1 849 |
| swap with restore evidence | 3 786 (242) | 3 821 (207) | **3 856 (172)** | 1 982 |
| Add 1, GHOST KeyPackage (395 B), 31 → 32 | 3 745 (283) | 3 780 (248) | 3 815 (213) | — |
| Add 1, KeyPackage at the 1 024 B bound, 31 → 32 | **4 374 (−346)** | 4 409 (−381) | 4 444 (−416) | — |
| Add 1, GHOST KeyPackage, 32 → 33 (beyond the cap) | 3 861 | 3 862 | 3 897 | 1 729 |
| context change: 8 committers, 3 funders, 48-byte name (446 B context) | 3 653 | 3 688 | 3 723 | 1 521 |
| **Remove 1 + that context change** (one unit, S0-16) | 3 578 (450) | 3 613 (415) | 3 648 (380) | 1 774 |
| **composite**: context change + Remove + restore swap | **4 178 (−150)** | 4 213 | 4 248 | 2 374 |
| composite + Add of a 1 024 B KeyPackage | 5 447 | 5 482 | 5 517 | 3 643 |
| Welcome for 1 joiner (tree included) | 8 818 (16 KiB) | 8 888 | 9 020 | 10 824 (16 KiB) |

**Threshold (blank, 32 leaves)** — Add with a 1 024 B KeyPackage: 3 800 B at 24 members, 3 964 at 26, **4 046 at 27**, 4 128 at 28, 4 374 at 31, 4 490 at 32; Add with a GHOST KeyPackage: 3 171 at 24 … 3 861 at 32; context change 2 997 … 3 653; restore swap 3 130 … 3 786. Each extra member adds 82 B (one HPKE ciphertext of a path secret). **At 128 leaves** the 1 024 B Add fits to 26 members (25 → 26: 3 952 B, margin 76) and not beyond (26 → 27: 4 034 B).

**Random histories (32, 60 steps):** the largest self-update/PCS commit seen was 2 857 B and the largest context change 3 325 B — below the blank shape, as the resolution argument predicts (a non-blank node with u unmerged leaves contributes 1 + u ≤ its leaves; the committer's ciphertexts are at most n − 1 in any shape). **The worst shape is the committer whose copath is blank in the widest tree** (the first run said "whose copath is blank" and missed the width).

**Numbers — large class, 100 members (128 leaves; margin to C(16384) = 16 316).** Blank: rank-255 self-update 3 560, PCS 8 831, Remove 8 756, rejoin swap 9 299, restore swap 9 432, **Add 99 → 100: 9 391 (GHOST KP) / 10 020 (1 024 B KP)**, context change 9 299, composite 9 824 — **all fit, margin ≥ 6 296 B**. (The first run's "largest single-proposal commit" was an Add from 100 to 101, 9 473 / 10 102 B, which the cap forbids.) Populated: 936 … 3 795 B. Welcome for 1 joiner: **25 894–26 523 B** (blank; the first run's upper value, 27 013 B, was the Welcome of the two-joiner composite), 33 612–33 684 B (populated) — the 64 KiB bucket, margin ≥ 31 784 B.

**Largest application messages.** A 16 000-byte text POST (16 027 bytes of `ChannelContent`) with `ChannelOrder` is a **16 198-byte** MLS message: margin **118 B** to C(16384) (98 B with `reply_to`); a media POST (84-byte `media_ref`, 1 024-byte caption) is 1 310 B.

**Worst Welcomes (review finding H10: the first run mislabelled them).** (a) Leaves that are KeyPackage leaves at the 1 024 B bound (a KeyPackage leaf stays in the tree until its member updates): the **batch** Welcome of n − 1 such joiners is 32 885 B at 32 members and **103 061 B at 100 (NO_FIT)**; the Welcome for **one** joiner into a tree that already holds such leaves is **27 696 B over 30 of them** (32 members, 64 KiB bucket) and **87 536 B over 98 (100 members, NO_FIT)** — no Welcome can be sent, so nobody can join or rejoin. (b) Leaves inflated by their own members (`v10_04_leaf_inflation_by_self_updates_100`): a rank-255 member's modified client adds an unknown extension (type listed in its own capabilities) to its update-path leaf in an empty self-update; the largest that still fits C(16384) adds 12 746–12 809 B. After 1, 2, 3, 4 such members the next one-joiner Welcome is 39 121, 51 891, 64 792, **77 625 B (NO_FIT)** — four members lock joins out of a blank 100-member channel. (A populated tree was not measured; the first run's "three in a populated tree" was not measured either and is withdrawn.) OpenMLS accepts every one of these self-updates, and CO-2 as written checked only the commit's size.

**Verdict: CORRECTS.**
- With the canonical KeyPackage, **every single-proposal commit fits the floor at both caps in every reachable width**; the tightest margins are **172 B** (restore swap, 32 members, 128 leaves) and 213 B (Add 31 → 32, 128 leaves).
- With §6.2.4's bound of 1 024 B, **a single Add exceeds C(4096) from 27 members** (26 in a 128-leaf tree) — exactly the case for which §5.7 said to lower the small cap and re-ask Q3 — and a 100-member tree of such leaves cannot be welcomed. The first run switched to canonical KeyPackages and declared Q3 "not re-asked"; the review pass (finding H7) re-asks Q3 with both options measured (canonical at 32, or 1 024 B at 26).
- The composite of §5.7 (context + Remove + swap) is 4 178–4 248 B > 4 028: it must split, which §5.7's rule does — **but §5.7's deferral order was wrong** (review finding I7): it deferred the context change before swaps, while CO-2 and §5.3 require a removed committer's or funder's key to leave the lists in the commit that removes it; the unit {Remove of P, drop of P's key} is 3 578–3 648 B and fits, so the swap must be deferred first.
- "Unmerged leaves" do not make commits larger than the blank tree; width does (+35 B per level).
- Welcomes were not bounded by anything in the design (leaf inflation by joiners or by members themselves), and the 64 KiB blob limit does not bound SRLabs S0-1's leaf-node vector.

**Correction S0-4 (folded: §0.4, D15, §3.8, §4.4, §5.5, §5.6, §5.7, §6.2.2, §6.2.4, §10.2 fn 4, §13.1 G-M7, R-2, R-19, Q3, E-14, E-21).** One definition of **the canonical GHOST KeyPackage** in §6.2.4 (B): capabilities exactly versions [mls10], suites [0x0003], extensions [0xF0A1, 0xF0A2, 0xF0A4], proposals [] (the encoded list is empty), credentials [Basic], in that order, no GREASE; the lifetime `[d − 4, d + 80]` in whole days; leaf extensions exactly [`GhostLeaf`]; KeyPackage extensions exactly [`GhostKpBind(channel_id, purpose, d)`] with the same d; 395 B, a size that follows from RFC 9420's encoding of these values (G-M7 checks at every pin that `keyPackage` still produces it); the `JoinRequest` codec refuses `kp_len ≠ 395`. §5.7's table replaced by the measured tables (32, 64, 128 leaves; 100 members); G-M7 pins the golden sizes (a bump that eats the 172-byte margin fails). §3.8 states the consequence (no extensibility inside a channel; RFC 9420 §13.5's GREASE omitted; the canonical form is per suite). Q3 re-asked.

**Correction S0-5 (folded: CO-2, §3.5, §3.7, §5.4, §5.7, §6.2.4, §12.5, T41, MM-38, L8-C11).** CO-2: **every leaf a commit installs is canonical** — an update-path leaf has exactly the canonical capabilities and exactly one extension, `GhostLeaf`; a KeyPackage an Add or a swap carries is the canonical KeyPackage. §5.4: `GhostLeaf` is the leaf's only extension. L8-C11 narrowed: a malicious member can send large valid posts up to 64 KiB but cannot enlarge the tree. §3.7, §5.7 and §6.2.4 no longer say the 64 KiB blob bounds S0-1. MM-38 with its killer GV and SCN-M20's Welcome-size assertion.

**Correction S0-16 (folded: §5.7, §10.2 fn 9, §19.18, MM-42).** §5.7 defers Adds from the end, then swaps, then the context change except the drops of keys whose Removes the commit keeps, then extra Removes with their drops.

*Effort:* S0-4 ≈ 0 net; S0-5 0.5 day (S4, S5); S0-16 0.25 day (S5).

---

## 5. V10-5: the cost of the value-semantics storage adapter

**Question.** How many rows does a call load, how large is the change-set it returns, how does the write amplification grow with retained past epochs, at 32 and 100 members, and what does a trial settle (CO-3) cost?

**Method.** `core/src/kv.rs` implements `GhostKv` as §3.4 specifies it: an in-memory map loaded from the channel's rows; every write, append and delete recorded into a net change-set; group-scoped vs global rows by method (every method that takes a `GroupId` is group-scoped; a group id other than the call's channel is refused); values wrapped as `nonce(12) ‖ ChaCha20-Poly1305(state key, AD = "ghost/v1/mls-kv" ‖ scope ‖ channel_id ‖ SHA-256(k), v)`; the `added_at` day rewrite in `write_message_secrets` (a `LayoutDrift` error when `message_secrets.added_at` is missing). Values are OpenMLS's serde entities as JSON (the memory provider's format). The harness (`Device::call`) runs every operation with value semantics: unwrap every stored row, load, run, wrap the change-set, apply only on success. `core/tests/v10_05_adapter.rs` measures a member M at 0, 2, 8 and 64 retained past epochs (`max_past_epochs(64)`, §3.5), blank and populated, 32 and 100 members, for: receive a 200-byte post, encrypt one, the validation run of a commit (CO-2, dry), a trial settle (process + merge + open one successor post, all discarded), the settle, M's own commit and merge, a load-only call, and `sweepPast(2)`. The same runs with an experimental **split** mode of `GhostKv` (past epochs stored one row per epoch, unchanged rows not rewritten) test a fix. **Review pass (finding H4):** the first run printed one measurement per call; on the loaded host two runs of the same configuration differed up to five times (141.5 vs 708.0 ms), and its 100-member "17.1 ms per received post" disagreed with V10-10's median of 3.85 ms for the same operation. Every operation now runs 9 times on the same state (rows restored between runs) with `rayon` at one worker, and the times below are **medians**; the bytes are deterministic up to the decimal lengths of random numbers in JSON (between the first run and the review run, rows loaded agree within 0.5 % and change-sets within 1 %).

**Numbers — structure.**
- **Methods.** The `StorageProvider` trait has 72 `fn`s (`ot:src/storage.rs`), of which **53 are required in the P0 feature set** (41 group-scoped, 12 global) plus the default `version()`; the other 18 exist only under `extensions-draft` (3) and `virtual-clients-draft` (15), both forbidden by §3.2 (asserted).
- **Rows.** An active member holds **11 group-scoped rows** per channel (`ConfirmationTag`, `EpochKeyPairs`, `EpochSecrets`, `GroupContext`, `GroupState`, `InterimTranscriptHash`, `MessageSecrets`, `MlsGroupJoinConfig`, `OwnLeafNodeIndex`, `ResumptionPsk`, `Tree`) and **no global row**: the KeyPackage's rows (the bundle with its private keys) exist only from `keyPackage` until the Welcome is processed; OpenMLS stores no signature key (GHOST's signer is its own).
- **Row sizes (JSON, blank; first run and review run):** `Tree` 40.7–40.9 KB (32) / 125.1–125.4 KB (100), 51.2–51.3 KB populated at 32; `MessageSecrets` 2.4 KB / 4.3 KB with no past epoch and **+18.4–18.6 KB (32) / +52.9–53.1 KB (100) per retained past epoch** (the review run's split rows: 18.5 KB and 52.9–53.0 KB each): OpenMLS keeps every past epoch's secret tree *and its full member list* inside that one row (`om:src/group/mls_group/past_secrets.rs`, `EpochTree { epoch, message_secrets, leaves: Vec<Member> }`).

**Numbers — per call (blank; bytes; medians of 9 on a loaded host, ms).**

| n | retained past epochs | rows loaded (plain) | received post: change-set, unsplit | split | received post | trial settle (merge + 1 successor) | settle |
|---|---|---|---|---|---|---|---|
| 32 | 0 | 47 363 | 3 340 | 3 355 | 0.88 | 7.69 | 4.98 |
| 32 | 2 | 84 289 | 40 232 | 3 314 | 3.48 | 13.88 | 10.32 |
| 32 | 8 | 195 202 | 151 079 | 3 361 | 8.86 | 27.22 | 15.66 |
| 32 | 64 | 1 230 452 | **1 186 346** | 3 499 | 34.44 | 106.94 | 58.16 |
| 100 | 0 | 134 464 | 5 513 | 5 513 | 0.83 | 6.19 | 4.00 |
| 100 | 2 | 240 662 | 111 679 | 5 533 | 2.61 | 13.17 | 7.93 |
| 100 | 8 | 559 369 | 430 371 | 5 555 | 16.50 | 39.76 | 16.61 |
| 100 | 64 | 3 534 241 | **3 405 217** | 5 719 | 92.47 | 300.36 | 174.17 |

- A settle writes 10 rows and deletes 3 (66 KB at 32, 187 KB at 100 with no past epoch, plus the whole `MessageSecrets`). The validation run of a commit also produces a change-set (the rewritten `MessageSecrets`), which CO-2 discards — confirmed necessary: re-processing the same commit at the settle succeeds only because the validation's ratchet consumption was not written (applying it makes the settle fail with a secret-reuse error).
- Wrapping is 5–15 % of a call; the rest is JSON (de)serialisation of the whole state.
- **Split mode:** a post's change-set is **3.3–3.5 KB at 32 and 5.5–5.7 KB at 100 whatever the retention** (64 epochs included), because a post changes only the current epoch's secret tree; `sweepPast(2)` then deletes 62 rows. **It saves I/O, not CPU:** OpenMLS hands the adapter the whole store at every write and reads it whole at every load, so every call still (de)serialises every retained epoch, and the spike's unoptimised split (it re-serialises each retained epoch to compare with its stored row) took **0.4–2.8 times** the unsplit call's median over the received posts, trial settles and settles measured, and **1.5–2.8 times at 100 members** (received post at 100 members: 1.53 / 7.42 / 24.21 / 183.98 ms at 0 / 2 / 8 / 64 retained). The CPU lever is the retention cap; the I/O lever the split.
- Populated at 32 (31–64 retained epochs after the populate): 0.58–1.19 MB per post; split: 3.4–3.5 KB.
- **The split behaves like the unsplit store** (the impact reviewer's R1 and R2, re-run and now tests): on every late-post path — two posts decrypted late and out of order six epochs later, the replay refused (`SecretReuseError`), a post of a swept epoch refused after `sweepPast(2)` (`TooDistantInThePast`), a post one epoch late after the sweep decrypted, equal epoch authenticators — both modes give identical results (`v10_05_split_matches_unsplit_on_late_posts`); and in the WG replay with 16 retained epochs the reassembled `MessageSecretsStore` is byte-identical in both modes after every call (295 of 295 states, V10-12).
- Reconciled with V10-10: at 100 members with 2 retained epochs a received post is 2.6 ms here and 3.85–5.8 ms (medians of 15, 1 000-byte post) in V10-10; the first run's 17.1 ms was a single loaded measurement.

**Verdict: CORRECTS.** The adapter works as specified (value semantics, change-sets, scopes, wrapping, the day rewrite all exercised, and the KAT replay of §12 passes through it, V10-12). But (a) §3.4 counted 72 methods; (b) the write amplification is not a per-row matter the design can ignore: with the hard cap of 64 past epochs a received post can write 3.4 MB to SQLCipher in a 100-member channel, and the per-call parse grows with retention (a received post 92 ms and a trial settle 300 ms at 100 members with 64 retained, on the host; CO-3 allows up to 8 candidates × 33 such loads per settle); (c) R-3's figures (57–261 KB) described 2 retained epochs only.

**Correction S0-6 (folded: §3.3, §3.4 points 1, 4, 8, §3.5, §5.6 CS-S5, §6.3.5, §6.3.6, §8.3, §9, §12.2, R-3, Q18, E-9, B.2).** 53 methods (`GhostKvScopeTest` enumerates them; a compile-time check fails if a feature adds methods); §3.4 point 8, past epochs one row each (a recorded deviation like point 5, pinned by G-M7); `max_past_epochs(64)` → **16**, and every literal that follows (CS-S5's ≤ 17 recognition candidates, `ch_epoch` ≤ 17 rows, own box keys ≤ 18, B.2's "cel mult 16", the declared loss of an epoch more than 16 behind); `mls_kv` becomes an ordinary rowid table (review finding I5: its values are 0.1–125 KB, and SQLite's guidance keeps WITHOUT ROWID rows under about 1/20 of a page, ≈ 200 B at 4 KiB); R-3 and Q18 quote the medians above.

**Correction S0-17 (review finding I5(d); folded: D5, §3.4 points 4 and 9, §6.3.2, §6.3.5, CO-3, §10.2 fns 6, 7 and 20, §10.4, RO-C, MM-43, R-3, Q18, Q26).** With one messaging actor for DMs and channels (D16), per-call reloads multiply: a peek pass of 128 blobs was 128 full parses, and CO-3 up to 8 × (1 + 32). `receive` therefore takes up to 32 application messages of one epoch in one call, and a new `trialCount` settles a candidate in memory and tries every held blob in one load; a batched call checkpoints the in-memory map before each item and restores it on that item's failure; `GhostKv` loads behind one interface so Q18's cache can be added later. Q18's cache is decided after the device step (at S2's exit if a phone is available, S0-11).

*Effort:* S0-6 1 day (S2); S0-17 1 day (S2 0.5, S4 0.25, S5 0.25).

---

## 6. V10-6: determinism under a seeded getrandom

**Question.** With the process-global ChaCha20 stream behind getrandom's custom backend and `rayon` at one worker, do two runs of a scripted world produce byte-identical commits, Welcomes and state (a first probe of §19.10's S2 work)?

**Method.** Feature `det` of the spike defines `__getrandom_v03_custom` (the symbol getrandom 0.4.3's `custom` backend calls, `getrandom-0.4.3/src/backends/custom.rs`): one ChaCha20 stream under a mutex, keyed by the world seed, logging the drawing thread. The example `det_world` (built with `RUSTFLAGS='--cfg getrandom_backend="custom"'`) creates a channel of 8 (batch add, Welcome), sends 3 posts, a self-update, a remove, an add with its Welcome and a remove against a tree with unmerged leaves, all with value semantics, and prints the SHA-256 of every message and of every member's full row set. `scripts/v10-06-determinism.sh` (added in the review pass; `core/Cargo.toml` named it before it existed) builds it and runs two separate processes per configuration.

**Numbers.**
- Graph: getrandom **0.4.3 is the only getrandom in `ghost-mls-spike`'s graph and in `ghost-dm-host`'s linked host graph** (`cargo tree -e normal,no-proc-macro`), so one custom symbol covers every draw; `rand` 0.10's `SysRng` (the provider's DRBG seed and reseed, `hpke-rs-libcrux`'s PRNG) goes through it. **Correction of the first run (review finding H12):** getrandom 0.2.17 is not "for other targets only": the test-only KAT crate links it on the Windows host through `openmls/test-utils` → `openmls_rust_crypto` → RustCrypto's `rand_core` 0.6, and also reaches it through the `openmls_test` proc-macro; it is not in `det_world`. A getrandom check (S0-7 (c)) must therefore look at the host library's graph with `-e normal,no-proc-macro`, not at every graph.
- **One rayon worker, same seed, two processes: identical output** — every message (e.g. self-update 1 065 B `a89df523f4249d7f`, Welcome 2 791 B `a590f4c0b7d9895f`), every member's rows, equal epoch authenticators (re-run in the review pass with the script: identical, and the same hashes).
- **Draws: 270 (8 640 B), 172 on the main thread and 98 on a second thread** — the rayon worker, where `treekem.rs` seals path secrets with an HPKE PRNG seeded from `SysRng` (design §3.3 confirmed).
- **Rayon's default pool (24 threads), same seed, two processes: the posts are identical but the commits, the Welcome and every member's state differ** — the workers draw in racy order (in the review pass's run the first self-update happened to match; the remove, the add, the Welcome, the second remove and all rows differed).
- **One worker but the `added_at` day rewrite switched off** (`GHOST_SPIKE_NO_DAY_REWRITE=1`): every message identical, **every member's rows different** — OpenMLS stamps `SystemTime::now()` into `MessageSecrets`.
- `std`'s `HashMap` keys (not drawn through getrandom) do not reach any output in this script.
- `det_world` fixes virtual day 20 720 (2026-09-24) to reproduce these hashes; OpenMLS checks KeyPackage lifetimes (`[d − 4, d + 80]`) against the host clock, so that day works until 2026-12-12. `GHOST_SPIKE_DAY` now sets another day, and outside §12.1's window the probe refuses to run instead of failing obscurely.

**Verdict: CONFIRMS** the design's approach (§12.1, §19.10), with three preconditions the design named only in part.

**Correction S0-7 (folded: §3.3, §3.6, §12.1, E-20).** §12.1 states the preconditions: (a) `rayon` at one worker; (b) the `added_at` day rewrite, a determinism requirement as well as T33's; (c) a single getrandom major in the host library's linked graph (today 0.4.3, symbol `__getrandom_v03_custom`), which G-R2 checks with `cargo tree -p ghost-dm-host -e normal,no-proc-macro`. *Effort:* 0.25 day (S2).

---

## 7. V10-7: portable libcrux in the provider's crates

**Question.** Do the libcrux crates the provider adds build portable-only on both triples, is §19.23's `libcrux-aes` hazard real, and should G-R3's inline rule be extended or extracted into a script?

**Method.** (1) Every added libcrux crate's manifest and sources read for build scripts, SIMD features, `target_feature`, `std::arch`/`core::arch` and CPU detection. (2) The `libcrux-aes` build script exercised on the host in a scratch target directory: variables set to "0", then the workspace `[env]` ("1") without a clean, then `cargo clean -p libcrux-aes`, then "0" again without a clean — reading `build/libcrux-aes-*/output` after each step. (3) Every Android build of V10-3 cleaned `libcrux-ml-kem`, `libcrux-sha3`, `libcrux-intrinsics` and `libcrux-aes` per triple first and printed their build-script outputs afterwards (again in the review pass's rebuilds). (4) The unstripped libraries searched for SIMD-named symbols.

**Numbers.**
- Build scripts: of the provider's crates only **`libcrux-aes` 0.0.9 has one** (`build = "build.rs"`): it emits `cargo:rustc-cfg=feature="simd128"` on aarch64 and `feature="simd256"` on x86_64 unless `LIBCRUX_DISABLE_SIMD128/256`, and has no `rerun-if-env-changed`. `libcrux-aead`, `-chacha20poly1305`, `-poly1305`, `-ed25519`, `-hkdf`, `-hmac`, `-hmac-drbg`, `-sha2`, `hpke-rs-libcrux` and `openmls_libcrux_crypto` have no build script and no SIMD or arch code.
- Stale cfg (host, x86_64): **simd256 → still simd256 after the variables changed → portable after the clean → still portable after the reverse change** — exactly F9 V-6's sequence for the other three packages.
- Android builds (every build of both runs, both triples): every `libcrux-{ml-kem,sha3,intrinsics,aes}` build output has **0 `cargo:rustc-cfg` lines**.
- Symbols (unstripped, both ABIs): no libcrux SIMD implementation; the only libcrux symbols with SIMD names are `libcrux_platform::platform::simd128_support` / `simd256_support` (CPU-query helpers, x86_64). The NEON/AVX2 symbols present belong to RustCrypto `chacha20`, `curve25519-dalek`, `memchr`, `ring` and `simd_adler32`, all in the baseline.
- AES-GCM (the only user of `libcrux-aes`) is reachable only through suites 0x0001 and the AES PQ suites, which GHOST never uses; it is linked because the provider dispatches on the AEAD at run time.

**Verdict: CONFIRMS** §19.23 (the `libcrux-aes` hazard is real and the clean lists must name it). **S0's decision** (asked by §13.1 G-M9 and §19.10): **extract the script**. The inline rule already exists in three workflows (`ci.yml:254`, `dm-emulator.yml:149,165,172,176-189`, `dm-privacy-gate.yml:114,197`), each with its own package list, and Phase 10 adds four packages' worth of builds (`mls-vendor-tests`, the channel gates, the emulator smoke); one script avoids five diverging copies.

**Correction S0-8 (folded: §3.8, §13.1 G-M9, §19.10, §19.23, E-23).** `ghost/scripts/gates/libcrux-portable.sh`, extracted in S2 from `dm-emulator.yml:176-189`: `--clean <target-dir> <triples…>` cleans the four packages per triple; `--check <build dirs…>` fails when any `build/<pkg>-*/output` of those packages carries `feature="simd128"` or `feature="simd256"`, or when none exists; every workflow that builds a client graph calls both; a negative fixture is in `self-test.sh`. *Effort:* 0.5 day (S2 gates).

---

## 8. V10-8: the bootstrap in the Welcome's GroupInfo

**Question.** Does `GhostBootstrap` (0xF0A3) passed through `CommitBuilder::create_group_info_with_extensions` reach the GroupInfo inside the Welcome, can the joiner read it, and does the committer's GroupInfo signature authenticate it?

**Method.** `core/tests/v10_08_bootstrap.rs`: a committer adds a joiner with the bootstrap as a GroupInfo extension; the joiner reads `ProcessedWelcome::unverified_group_info().extensions()`, then `JoinBuilder::build()` (with `skip_lifetime_validation()`) and `into_group`. Authentication: the committer's signer corrupts the n-th signature of the next commit (n = 1 … 4) and the joiner's result is recorded. Two more cases: the same with `create_group_info(false)` after the extensions, and a plain commit's exported GroupInfo. **Review pass (finding I1):** a Welcome built by someone else — `v10_08_forged_welcome_and_the_committer_anchor`.

**Numbers.**
- The bootstrap (45 B) arrives in the Welcome's GroupInfo and the joiner joins (Welcome 2 007 B at 4 members; the joiner's epoch authenticator equals the committer's).
- Corrupted signature #1 (the update-path leaf): the joiner refuses (`PublicGroupError(TreeSyncError(RatchetTreeError(InvalidNodeSignature)))`), and so do members (`ValidationError(UpdatePathError(SignatureError(…)))`). #2 (the commit's FramedContent): the joiner **accepts** — a joiner never sees the commit. **#3 (the Welcome's GroupInfo): the joiner refuses with `PublicGroupError(InvalidGroupInfoSignature)`**. #4 (the exported GroupInfo): the joiner accepts.
- `create_group_info_with_extensions` also turns on OpenMLS's **exported** GroupInfo (with the ratchet tree and an `ExternalPub` extension; 1 869 B at 4 members). With `create_group_info(false)` after it, no exported GroupInfo is built and the bootstrap still reaches the Welcome.
- With `use_ratchet_tree_extension(true)` (§3.5) **every** commit, with or without Adds, builds an exported GroupInfo by default (1 255 B at 3 members; OpenMLS derives the external key pair for it). `create_group_info(false)` turns it off.
- Upstream's own test of `create_group_info_with_extensions` (`openmls/src/group/tests_and_kats/tests/group.rs:905-906`) is `#[ignore]`d at the tag commit (also in the `all-ciphersuites` run of V10-12: ignored for every provider), so GHOST's test is the only coverage of this path.
- **A forged Welcome (review pass).** RFC 9420 §12.4.3.1 verifies the GroupInfo signature against the `signer` leaf of the ratchet tree **the same Welcome carries**. A holder of the generation's join key `JK_g` who is not a committer — an invite holder of g, a member removed at the end of g, a current member — can open the joiner's join request (mode 0x12), create **its own group with `group_id = channel_id`** and a well-formed `GhostChannelContext`, add the joiner's KeyPackage and deposit the Welcome (mode 0x13). Measured, two variants (the forger's context naming itself as committer; the real committers list copied): **OpenMLS's `JoinBuilder::build()` accepts both** (the GroupInfo verifies under the forger's own leaf; the channel id matches; a bootstrap naming a newer generation is "authenticated" by that signature). **Applied, the forged join consumes the KeyPackage** (its rows 1 → 0), and **the real Welcome, sent later by the real committer, then fails with `NoMatchingKeyPackage`**: the joiner is captured and posts into the forger's group. With the **committers anchor** — the digest of the joined context's `committers` must equal the digest the invite carried, and the GroupInfo signer's key (`StagedWelcome::welcome_sender`) must be among them — both forgeries are refused ("committers digest differs from the invite's"; "GroupInfo signer is not a committer") in dry calls that write nothing, the KeyPackage stays, and the real Welcome passes the anchor and joins (equal epoch authenticators). `K_boot(e)` never closed this: a fabricated group has its own exporter.

**Verdict: CORRECTS** (the first run said CONFIRMS). The primary path works and a corrupted GroupInfo signature is refused, so the `K_boot(e)` fallback is not needed; but "authenticated by the committer's GroupInfo signature" was not established — V10-8 had corrupted only signatures made by the legitimate committer. The signature confirms transport integrity for whoever signed; the design needs an anchor for *who* may sign.

**Correction S0-9 (folded: §0.4, §3.5, §5.2, §5.4, §5.6, §10.2 fns 5 and 9, §12.2, §13.1 G-M2, §19.16, §19.25, PC-17, ADR-43, E-19).** The bootstrap travels only in the Welcome's GroupInfo; `K_boot(e)` and `boot_flag` are withdrawn (`WelcomeBlob = version ‖ kp_ref_len ‖ kp_ref ‖ welcome_len ‖ welcome`); every commit calls `create_group_info(false)` after `create_group_info_with_extensions`, and G-M2 refuses `export_group_info` and `into_group_info*`; PC-17 redefined; the V10-8 tests move into `ghost-client-mls` and G-M7. *Effort:* −0.25 day.

**Correction S0-15 (folded: D10, P-C5, §2.1, §5.2, §5.4, §5.5, §5.9, §6.2.1, §6.2.4, §6.2.5, §6.7, §6.12, CO-2, CO-5, §9, §10.2 fns 5 and 14, §10.4, §12.1, §12.6 JN, T39, PC-19, MM-41, R-20, Q41, L8-C25, ADR-43).** The invite gains `committers_digest(32)` = `SHA-256("ghost/v1/ch/committers" ‖ channel_id ‖ u8(k) ‖ committers…)` (254 … 302 bytes), and `INVITE_ISSUED` a TLV with the same digest. The joiner (`welcomeJoin`) accepts a Welcome only if the joined context's committers hash to the invite's digest and the GroupInfo signer's key is among them; a rejoiner requires the signer among the committers of its last final epoch; a refused Welcome is `INVALID_WELCOME` and writes nothing. The admitting committer admits only while its pre-commit committers match the invite's digest; a commit carrying an Add or a restore swap leaves `committers` unchanged (CO-2); a settle that changes `committers` voids every unconsumed invite whose digest no longer matches (CO-5). Residue: a committer named at the invite's issue — even one removed since — can still capture the joiner until the invite expires (L8-C25); a change of committers voids outstanding invites (Q41). New ModelRelay mode FAKE_WELCOME with JN cases and mutant PC-19. This is a new protocol rule for the next review's protocol lens. *Effort:* 0.75 day (S4 0.5, S5 0.25).

---

## 9. V10-9: OpenMLS's post-quantum suites with the libcrux provider (evidence for Q2)

**Question.** Do 0x004D (OpenMLS's X-Wing code point) and 0x004F (the WG draft's provisional TBD1) work with the libcrux provider, and what do GHOST-shaped commits cost?

**Method.** `core/tests/v10_09_pq.rs` (feature `pq`): for 0x004D, 0x004F and 0x004E (TBD2, also present in `ot:src/types.rs`), the KEM each maps to, `supported_ciphersuites()` and `supports()`, then a blank world of 20 and of 32 members with GHOST's configuration and extensions: a PCS commit, a Remove, an Add with evidence (and its Welcome), each validated by a member, then a self-update merged by all and a post decrypted end to end (asserted).

**Numbers (bytes).**

| Suite | KEM | listed | `supports()` | KeyPackage | n | PCS | Remove | Add + evidence | Welcome | end to end |
|---|---|---|---|---|---|---|---|---|---|---|
| 0x004D X-Wing, ChaCha20 | `XWingKemDraft6` | yes | Ok | 2 765 | 20 | 30 006 | 28 842 | 33 018 | 37 986 | yes |
| | | | | | 32 | 44 060 | 42 896 | 48 291 | 56 447 | yes |
| 0x004F ML-KEM768+X25519, AES-128-GCM | `XWingKemDraft6` | **no** | Ok | 2 765 | 20 / 32 | same as 0x004D | | | | yes |
| 0x004E ML-KEM768+X25519, AES-256-GCM, SHA-384 | `XWingKemDraft6` | **no** | Ok | 2 765 | 20 | 30 361 | 29 180 | 33 389 | 38 162 | yes |
| | | | | | 32 | 44 619 | 43 438 | 48 866 | 56 639 | yes |

- **All three code points map to the same HPKE KEM** in `openmls_traits` 0.6.0 (`ot:src/types.rs:788-794`: `XWingKemDraft6`), and the provider's `supports()` checks the AEAD, the signature scheme, the hash and the HPKE AEAD, **never the KEM** (`openmls_libcrux_crypto-0.4.0/src/crypto.rs:64-86`), so "`supports()` Ok" says nothing about the KEM, and "end to end" is one implementation talking to itself: conformance to the KEMs the WG draft assigns to TBD1/TBD2 was not tested (review finding H9; the first run said "the WG code points work").
- Every PQ commit needs the 64 KiB bucket already at 20 members; each member adds ≈ 1.17 KB to a blank-tree commit, so an Add stays within C(65536) up to ≈ 46 members and a Welcome up to ≈ 38.
- The PQ KeyPackage (2 765 B) is larger than §6.2.4's 1 024 B bound (and than S0-4's canonical size): the canonical form is per suite.
- The feature adds no package and 16.8 / 37.0 KB of code (V10-3).

**Verdict: CONFIRMS** D3 and §4.2 (classical in P0) with corrected numbers and wording; nothing changes the decision (TBD code points, outside the audit, 64 KiB blobs from 20 members).

**Correction S0-10 (folded: D3, §4.1, §4.2, §4.4, Q2, E-11).** §4.1's facts and sizes replaced by the measured ones and the KEM mapping; §4.4 gains the triggers "the suite's canonical form measured" and "checked against the WG draft by a second implementation or vectors"; Q2's text "cap ≈ 32" → "64 KiB blobs from 20 members, cap ≈ 38–46". *Effort:* none.

---

## 10. V10-10: timings on the host, the emulator and a low-end device

**Question.** How long do the native calls take at 20 and 100 members on the host, and on one low-end Android device if available?

**Method.** `core/tests/v10_10_timings.rs`: blank worlds of 20 and 100 members and a populated one of 20, retention swept to 2 past epochs at the measured members, rayon at one worker, value semantics with wrapping; each operation repeated 15 times on the same state (dry calls restore the rows); min / median / max. `core/examples/device_probe.rs`, built with cargo-ndk for x86_64 and arm64, pushed with `adb` to the **x86_64 emulator** (AVD `ghost-dm-api29`, Android 10, WHPX, 4 cores, 4 GiB, port 5574; the API 35 AVD was in use by another session and was left alone) and run from `/data/local/tmp`; the pushed binary's SHA-256 (`96c1e890…1019`) equals the built one. No low-end device is attached to this host. **Review pass (finding H6):** a third host run, and `v10_10_retention_effect_20_populated` (the same populated world with and without the retention sweep, twice alternately).

**Numbers — host (loaded; medians of 15, ms; the first run's second pass and the review pass's run).**

| Operation | n = 20 blank | n = 20 populated | n = 100 blank |
|---|---|---|---|
| keyPackage | 0.22 / 0.47 | 0.17 / 0.13 | 0.37 / 0.20 |
| commit: PCS self-update | 6.54 / 8.22 | 4.38 / 3.74 | 33.70 / 22.35 |
| commit: Add 1 + Welcome | 8.79 / 8.81 | 4.73 / 6.22 | 30.66 / 35.99 |
| commit: Remove 1 | 7.16 / 6.79 | 4.37 / 6.27 | 28.46 / 35.18 |
| validation run (CO-2) | 3.66 / 4.32 | 3.53 / 4.73 | 8.39 / 9.63 |
| settle (process + merge) | 3.99 / 5.42 | 3.43 / 5.53 | 12.91 / 13.40 |
| welcomeJoin (1 joiner) | 3.56 / 4.75 | 3.39 / 7.54 | 13.43 / 21.78 |
| encrypt post (1 000 B) | 1.40 / 1.80 | 0.91 / 1.30 | 3.89 / 4.00 |
| decrypt post (1 000 B) | 1.74 / 2.18 | 1.33 / 1.88 | 3.85 / 5.82 |

**Retention matters (correction of the first run).** The first run's text said its first pass (before the retention sweep was added) gave medians "between 0.4 and 1.0 times" the reported ones. **That was false:** its two logs give ratios of **0.32–6.81**, and the first pass's 20-member populated rows, where members still held the ≈ 20 past epochs the populate leaves, were 1.9–6.8 times slower (encrypt 6.20 vs 0.91 ms, decrypt 6.34 vs 1.33, settle 12.51 vs 3.43). Re-measured in the review pass (`v10_10_retention_effect_20_populated`: four populated 20-member worlds built alternately without and with the sweep to 2): every call on an existing member was **1.2–16.5 times** slower when it held the ≈ 20 past epochs the populate leaves than with 2 (e.g. decrypt 5.54 vs 0.76 and 7.44 vs 1.81 ms; settle 8.97 vs 6.23 and 16.93 vs 2.38 ms); `keyPackage` and `welcomeJoin`, which run on a fresh device, were not slower — the per-call parse of V10-5, and the reason for S0-6's cap of 16. No host figure bounds a call.

**Numbers — x86_64 emulator (API 29; medians of 9, ms).** The 3-member cycle (create, admit, post and AAD check, self-update, remove, add; epoch authenticators equal): **OK** in 27.9 / 54.8 ms. n = 20: PCS commit (2 201 B) 8.30, settle 4.25, decrypt 1.00, encrypt 1.87. n = 100: PCS commit (8 831 B) 30.74, settle 25.05, decrypt 7.60, encrypt 7.72; building the 100-member world 2.67 s. (Reproduced by the honesty reviewer from the committed source on the same AVD: the same commit sizes and equal authenticators.)

**Verdict: INCONCLUSIVE** for devices (none available; an x86_64 emulator on this host is not a low-end phone and runs no arm64 code), recorded for the host and the emulator. What was established: OpenMLS, the libcrux provider and `GhostKv` **run on Android's bionic libc** (x86_64) through every call with correct results — the first execution of the stack on Android in GHOST (R-9: upstream builds Android targets without testing them). On F9's 15–25× factor, a 100-member channel would cost 0.3–0.9 s per commit built, 0.2–0.35 s per settle and 60–150 ms per post on a low-end phone with 2 retained epochs (estimate, not a measurement), and several times more with 16.

**Correction S0-11 (folded: §12.11, §12.12, R-3, Q18, Q20, E-22).** §12.12's row "performance on low-end phones": host medians and the emulator figures, low-end phones **not measured**; §12.11: the arm64 `device_probe` built, not run; S2 builds its successor over `ghost-client-mls`, and the owner runs it at S2's exit if a phone is available, so Q18's cache decision has a device figure before S3–S7 build on value semantics (review finding I5(e)); R-3's residue. *Effort:* 0.25 day (S2).

---

## 11. V10-11: OpenMLS's wall-clock sites against the anchored virtual time

**Question.** Are KeyPackages from each end of a world's day range accepted on the host clock (§12.1: first virtual day ≥ host − 79, last ≤ host + 3)? How does a lifetime failure surface, and can GHOST map it to `LIFETIME_PENDING` as CO-2 requires ("refused **only** for a KeyPackage lifetime")? Joins?

**Method.** `core/tests/v10_11_lifetimes.rs` (every outcome below asserted since the review pass). (a) KeyPackages made on virtual days host−81 … host+6 with GHOST's lifetime `[d−4, d+80]`, parsed by a committer (`KeyPackageIn::validate`). (b) An Add of a KeyPackage valid for 3 more seconds, committed while valid; receivers validate before and after expiry; the same commit also built with signature #1 (update-path leaf) or #2 (FramedContent) corrupted. (c) A KeyPackage valid only from now + 1 h. (d) A 100-year lifetime. (e) A member admitted with a 3-second KeyPackage that never updates, then a later joiner's Welcome with and without `skip_lifetime_validation()`, and an existing member processing that commit.

**Numbers.**
- (a) Accepted from host−79 to host+4; refused at host−80 (`LifetimeError(Expired { not_after: …, now: … })`) and host+5 (`NotValidYet`). §12.1's range holds with a day of margin at the top.
- (b) Before expiry: valid; after expiry the receiver's error is **`ValidationError(KeyPackageVerifyError(LifetimeError(Expired { … })))`** — typed, so a mapping exists. **Ordering:** with the update-path leaf signature also corrupted, the receiver reports **only the lifetime error**; with the FramedContent signature corrupted it reports `InvalidSignature` first. OpenMLS validates each Add's KeyPackage (`KeyPackageIn::validate`, `om:src/key_packages/key_package_in.rs:195-197`, reached from `om:src/messages/proposals_in.rs:177` while the content is decoded) after checking the commit's signature but **before** verifying the update path, the proposal set, the capabilities and everything GHOST's CO-2 checks afterwards: a lifetime refusal says nothing about the rest of the commit. And the same commit is valid for a receiver whose clock is before the expiry and refused for one after it: device time decides.
- (c) A KeyPackage not yet valid: `LifetimeError(NotValidYet …)` at the committer's parse.
- (d) **OpenMLS never checks the span**: `Lifetime::has_acceptable_range()` (`om:src/key_packages/lifetime.rs:116`) is called nowhere in the crate; a 100-year KeyPackage is accepted by the committer and its Add by receivers. (All 1 550 Add KeyPackages of the WG passive-client vectors carry `[0, u64::MAX]`, V10-12.)
- (e) The default `JoinBuilder` refuses a tree with an expired never-updated leaf (`PublicGroupError(LeafNodeValidation(Lifetime(Expired …)))`); with `skip_lifetime_validation()` the join succeeds; existing members process the commit (the tree's old leaves are not re-validated).

**Verdict: CORRECTS.** The range (a) and the join rule (e) are confirmed. But CO-2's rule "if OpenMLS refuses it **only** for a KeyPackage lifetime (`LifetimeError`) … the candidate is *lifetime-pending*: **ranked as valid**, never merged, and the member is `clock_blocked` while it would win" cannot be implemented as stated: the refusal masks other defects (measured), so a committer can send an otherwise-invalid commit carrying an expired KeyPackage and every member whose clock rejects it stalls for as long as it would win. **The first correction (a pending candidate becomes invalid once the member's trusted day passes its expiry) was not enough (review finding I2):** a member whose OpenMLS *accepts* never consults its trusted day, so a malicious committer that admits a KeyPackage expiring at midnight — with a backdated `commit_minute` so that CO-2 (A)'s admission window holds — splits a member with a correct clock (lifetime-pending, later invalid; it merges the competitor) from a member whose clock is minutes slow (OpenMLS accepts; it merges the commit). And the span and day-alignment checks that §6.2.4 (B) and §6.2.5 leave to the admitting committer and to joins are not made by OpenMLS for received Adds at all, while CO-2 (A) did not make them either.

**Correction S0-12 (folded: C-15, CS-C3, §3.5, §3.6, CO-2, CO-4, §6.2.4, §9, §12.3, §12.4, §19.4, T41, MM-27, MM-39, MM-40, R-14, L8-C20, ADR-40, ADR-42).** (1) CO-2 (A): every KeyPackage an Add or swap carries is the canonical KeyPackage — whole-day bounds, span exactly 84 days (`[d − 4, d + 80]`), and d within `[commit_day − 7, commit_day + 3]` of the commit's `commit_minute`. (2) **One predicate on the member's trusted day t, on both branches of OpenMLS's answer:** the KeyPackage is *accepted by the trusted day* iff `t < not_after_day` and `not_before_day ≤ t + 3`; if not, the commit is **invalid** whatever OpenMLS answered; if it is accepted and OpenMLS refuses with `LifetimeError`, the candidate is lifetime-pending — ranked by `(rank, hash)` only, never merged or counted as valid in CO-3, the member `clock_blocked` while it would win — until OpenMLS accepts it or the trusted day stops accepting it. Honest clocks are within σ = 3 d of true time (F7:58), so an honest KeyPackage starts at most 2 days after any honest member's trusted day and expires far after any processing: **honest commits are judged alike**; a malicious committer can split members whose trusted days straddle a bound it chose (at most 2σ apart; detected by CO-11/CO-12; declared in L8-C20). (3) CO-4: a pending candidate blocks the settle only while it would win. (4) EM-3 gains trusted days and the otherwise-invalid and otherwise-valid near-expiry adversaries; MM-27 redefined, MM-39 (span unchecked) and MM-40 (predicate on one branch only) added. (5) **Declined:** making `commit_minute` monotonic against the previous epoch's — a committer that dates one commit into the future would push every later honest commit's minute forward and, through CO-2 (A)'s window, invalidate every honest KeyPackage until real time caught up. *Effort:* 0.75 day (S5).

---

## 12. V10-12: the MLS WG passive-client vectors through `GhostKv`

**Question.** Does the WG's passive-client replay pass through `GhostKv` under value semantics (the `ghost-client-mls-kat` crate of §10.1), and which vectors and epochs are valid on the host clock?

**Method.** `scripts/v10-12-fetch-vectors.sh` fetches `passive-client-welcome.json`, `passive-client-handling-commit.json` and `passive-client-random.json` from the openmls repository at `3a3e35de…` and verifies each against the tree's git blob id (`15bbfcf0…`, `c702dcc3…`, `ea20d752…`; SHA-256 `92ebb04b…849c`, `b24949fd…da21`, `0095d863…d3c1`). `kat/tests/passive_client.rs` (crate `ghost-mls-spike-kat`, the only one with `openmls/test-utils`, for `KeyPackageBundle::new`) injects each vector's KeyPackage and private keys into a fresh `GhostKv`, joins with `JoinBuilder::skip_lifetime_validation()`, then processes every proposal (`store_pending_proposal`, KAT-only) and commit, each call under value semantics (fresh adapter, stored rows, change-set applied on success), and after **every** call runs the **fingerprint half** of the reload oracle of §3.4 point 6 (the in-memory group against one reloaded from the rows: epoch, epoch authenticator, tree hash, own leaf, an exporter output). A trial join without `skip_lifetime_validation()` is made on a copy of the rows. **Review pass (findings H8, I8):** the test asserts every total below (it only printed before), counts vectors and epochs per suite, and replays every vector twice more with 16 retained past epochs, unsplit and split, comparing the reassembled `MessageSecretsStore` byte for byte after every call. Separately, OpenMLS's own tests ran from a shallow checkout at `3a3e35de` (verified `git rev-parse`): `cargo test --locked --release -p openmls --lib --features test-utils,libcrux-provider -- kat read_vectors vectors`, and in the review pass the whole lib suite with `all-ciphersuites`.

**Numbers.**
- 148 vectors: 56 welcome, 91 handling-commit, 1 random; suites 0x0001 … 0x0007. The libcrux provider supports 0x0001 and 0x0003 only; **105 vectors (suites 0x0002, 0x0004 … 0x0007, 21 each) cannot run** with it.
- **All 43 vectors of the provider's suites replay fully**: welcome 8 + 8 (joined, initial epoch authenticator equal), handling-commit 13 + 13 (26/26 epochs each), random 1 (0x0001, 200/200 epochs); **252/252 epoch authenticators equal**, **1 861 reload-oracle checks, all equal**. **Per suite: 0x0001 22 vectors, 226 epochs; 0x0003 — GHOST's suite — 21 vectors, 26 epochs.**
- **With 16 retained past epochs**, unsplit and split: 252/252 epochs each, and **295 of 295** reassembled `MessageSecretsStore` states byte-identical; the random vector ends with 16 past epochs held.
- **No clock dependence for commits:** all 1 550 Add KeyPackages in the replayed commits carry the lifetime `[0, u64::MAX]`.
- **Joins:** 42 of the 43 Welcomes are refused without `skip_lifetime_validation()` (expired leaves in their trees); GHOST's join path uses that switch anyway (§19.4 rule 3).
- OpenMLS's own tests at the tag: **371 passed, 0 failed, 6 ignored** with the MTI suite; their parametrised tests ran suite **0x0001 only** — `openmls_test` collapses to the MTI suite unless the `all-ciphersuites` feature is on (`openmls_test/src/lib.rs:8-19`). **With `test-utils,libcrux-provider,all-ciphersuites` (review pass): 1 149 tests, 1 134 passed, 0 failed, 15 ignored (37 s after a 6.5-minute build); suite 0x0003 with the libcrux provider 213 passed, 3 ignored** (among the ignored, upstream's `test_create_group_info_with_extensions` for every provider).
- Licence of the vectors: the `mlswg/mls-implementations` repository declares no licence (GitHub licence API: none); the copies are in the MIT-licensed openmls repository. They are test data only and never distributed.
- **What the replay proves and does not (review finding I8).** It proves that the adapter — value semantics, scopes, the day rewrite, the split of past epochs — carries OpenMLS's own processing of independently produced commits without loss, with the fingerprint half of the reload oracle after every call. It does **not** run the oracle's behavioural half (a reloaded group decrypts the next message and refuses a replay): the vectors carry no application messages; that half runs in the spike's own worlds (V10-5's late-post test, under value semantics every call is a reload). And it does **not** test GHOST's join path: it joins through OpenMLS's `JoinBuilder` with the vectors' configuration (mixed plaintext, 16 resumption PSKs, day 0), and every vector would fail `welcomeJoin`'s structural checks and CO-2 (A) (lifetimes `[0, u64::MAX]`, no `GhostLeaf` or `GhostKpBind`).

**Verdict: CORRECTS** — in the design's favour, with limits. The design expected a clock-dependent subset; the subset is set by the provider's suites, and within it every vector and epoch passes through `GhostKv` with value semantics and the fingerprint oracle. GHOST's own suite gets 26 epochs of it; OpenMLS's suite at 0x0003 complements that.

**Correction S0-13 (folded: §3.4 point 6, §10.1, §12.2, §13.2, §13.3, §14 S2, §15 item 7, §19.10, Q22, ADR-40, E-24).** §12.2 item (2): the replay runs every vector of the provider's suites (43 of 148, 252 epochs), names the 105 others as not applicable, and states what it proves and does not; §10.1 forbids wiring the KAT crate to `welcomeJoin`; `mls-vendor-tests.yml` runs `cargo test --locked -p openmls --lib --features test-utils,libcrux-provider,all-ciphersuites`; §13.3 records the vectors' licence; Q22 is re-asked with 0x0003's coverage. *Effort:* none (the KAT crate is sized in S2).

---

## 13. V10-13: `refresh_epoch`, `GhostKpBind`, and the AAD round trips

**Question.** Does `GhostLeaf.refresh_epoch` set through `leaf_node_parameters` reach the update-path leaf and read back from the staged commit? Is `GhostKpBind` (0xF0A4) accepted as a KeyPackage extension? Does `set_aad` on commits round-trip through `ProcessedMessage::aad`, and on application messages is `ChannelOrder` readable before decryption through `PrivateMessageIn::aad` and reset after each message?

**Method.** `core/tests/v10_13_ext_aad.rs` over a 3-member world (14 assertions).

**Numbers.**
- `GhostKpBind` (38 B) is accepted; the GHOST KeyPackage is 395 B. A KeyPackage whose leaf capabilities omit 0xF0A4 is **built** by OpenMLS's `KeyPackageBuilder` without complaint and **refused** at the committer's `KeyPackageIn::validate` (`UnsupportedExtension`).
- A self-update with `refresh_epoch = e` through `leaf_node_parameters`: the receiver reads `GhostLeaf` from `StagedCommit::update_path_leaf_node()` and decodes `refresh_epoch = e`.
- `GhostCommitAad` (8 B without evidence) set with `set_aad` round-trips byte for byte through `ProcessedMessage::aad()`; `stage_commit` resets the AAD, and the committer's next message carries none; the AAD is not persisted (a reloaded group has an empty AAD).
- `ChannelOrder` (9 B): read from `MlsMessageIn → PrivateMessageIn::aad()` before decryption together with the header's epoch and content type (`Application`); equal to `ProcessedMessage::aad()` after decryption; the decrypted sender equals `sender_leaf`. `set_aad` applies to exactly the next message: the second `create_message` without `set_aad` carries 0 AAD bytes.

**Verdict: CONFIRMS** all four clauses. No correction; one note for S2: `keyPackage` (§10.2 fn 4) must list 0xF0A4 in the leaf capabilities because OpenMLS's builder does not check it (the canonical capabilities of S0-4 do).

---

## 14. V10-14: occupancy of the self-hosted runners

**Question.** How much of the four self-hosted runners do the existing workflows use, measured, before Phase 10 adds `channel-exit-gate`, `channel-privacy-gate`, `channel-state-models`, fuzzing and weekly vendor tests?

**Method.** First run: `scripts/v10-14-nightly.sh 14` fetched, through the GitHub API, every run **started by `schedule`** of the eight scheduled workflows and every job's runner, start, end and result (307 jobs), summed per night. **Review pass (findings H1, I4):** that crawl missed the push-triggered runs of the same workflows on the same runners, so it blamed the night load for queues other runs built. `scripts/v10-14-crawl.sh 2026-09-14` now fetches **every run of every trigger** (schedule, push, pull_request, workflow_dispatch) and every job of every attempt with its creation, start and end (1 370 jobs, crawled on 2026-09-26 after the nights of interest had ended; the night of 09-26 was still running and is left out), and `scripts/v10-14-aggregate.awk` computes per UTC day and per night the runner-minutes on `ghost-runner-1 … 4` by trigger, the delay from each cron to its run's creation, the runner-minutes by hour of day, and the minutes in which a job waited while no runner was busy. Jobs on GitHub-hosted runners (before 2026-09-17) are excluded.

**Numbers — per UTC day, by trigger (runner-minutes; share of 4 × 1 440).**

| Day | busy | share | schedule | push | dispatch |
|---|---|---|---|---|---|
| 09-17 | 1 218 | 21 % | 1 218 | — | — |
| 09-18 | 1 111 | 19 % | 1 111 | — | — |
| 09-19 | 2 068 | 36 % | 1 295 | 601 | 173 |
| 09-20 | 5 510 | **96 %** | 2 153 | **2 957 (54 %)** | 400 |
| 09-21 | 5 594 | **97 %** | 1 820 | **3 774 (67 %)** | — |
| 09-22 | 2 792 | 48 % | 1 852 | 940 | — |
| 09-23 | 5 034 | **87 %** | 2 035 | **2 999 (60 %)** | — |
| 09-24 | 5 422 | **94 %** | 2 115 | **3 307 (61 %)** | — |
| 09-25 | 4 324 | 75 % | 2 629 | 1 694 | — |

**Numbers — per night as the first crawl defined it** (the UTC date of the scheduled runs' creation; window = first scheduled run created → last scheduled job ended):

| Night | scheduled jobs | scheduled runner-min | T2 share | window | longest queue wait | every job in the window: schedule / push |
|---|---|---|---|---|---|---|
| 09-17 | 25 | 1 218 | 92 % | 5.5 h | 236 min | 1 218 / 0 |
| 09-18 | 25 | 1 111 | 91 % | 5.1 h | 220 min | 1 111 / 0 |
| 09-19 | 25 | 1 295 | 89 % | 5.8 h | 238 min | 1 295 / 0 |
| 09-20 | 18 | 2 331 | 91 % | **25.2 h** | **1 403 min** | 2 331 / **3 687** |
| 09-21 | 26 | 1 643 | 84 % | 15.4 h | 835 min | 1 727 / **1 962** |
| 09-22 | 26 | 1 852 | 92 % | 9.7 h | 425 min | 1 852 / 464 |
| 09-23 | 40 | 2 035 | 82 % | 12.7 h | 689 min | 2 035 / **1 010** |
| 09-24 | 40 | 2 735 | 74 % | **21.9 h** | **1 226 min** | 2 735 / **2 506** |
| 09-25 | 40 | 2 009 | 61 % | 10.3 h | 532 min | 2 009 / 452 |

(The first run's 09-24 row — 39 jobs, 2 720 min, 19.6 h, 1 122 min — was crawled while a job was still queued; its spans ran from the first job's start, these from the first run's creation.)

- **Cron delays:** every scheduled run was created **275–340 minutes after its cron** (e.g. `t2-exit-gate`, cron 02:17 UTC, runs created 07:18–07:56 UTC; all eight workflows alike). 89.4 % of the **scheduled** runner-minutes fell between 07:00 and 20:00 UTC and 1.2 % between 02:00 and 07:00 — the "nightly" gates run in the owner's day (UTC+3), next to the development pushes. Over every trigger the shares are 65.5 % (07–20), 15.5 % (02–07) and 19.0 % (20–02).
- **What the long waits are:** on 09-20 the last scheduled T2 job ended at 19:53 UTC and the queued scheduled entitlement shards started only the next morning (seven were cancelled after 24 h); in between, all four runners ran **push-triggered** jobs — T2 pair 0 (2–4 h each) and its mutants, entitlement shards, `ci`. In the nine days, **a job waited with no runner busy for one minute**; all four runners were busy 8 052 of 12 960 minutes. The queues are the push load, not an idle laptop (the impact reviewer's "about 1 320 minutes queued with no runner active" came from the schedule-only crawl and is rejected).
- **Push triggers:** on every push to `main`, `t2-exit-gate` (pair 0 and mutants; 6 983 runner-minutes over the period), `entitlement-exit-gate` (12 shards; 4 177), `ci` (3 213) and `messaging-exit-gate` (2 418) run; 38 pushes between 09-16 and 09-26, 5 of them touching only documents.
- Medians per scheduled job (self-hosted, runs created 09-17 … 09-25): `t2-exit-gate` 127 min over 99 jobs (max 240 = its timeout, once: seed pair 0 on 09-20, cancelled), `signer-timing` 12, `monero-regtest` 15, `entitlement-exit-gate` 10.5, `dm-state-models` 4; `messaging-exit-gate` ran three times: 105, 481 (cancelled at its 480-minute timeout) and 265 minutes (the first run's schedule-only crawl, over a different window, quoted 134, 11, 14, 10, 3 and "median 104" over two runs).
- **The DM gates are arriving:** `dm-privacy-gate`'s T32 world jobs failed within 1–2 minutes through 09-24 and **ran 28–43 minutes each on 09-25** (still failing), so its designed load (by §13.2's timeouts 10 × 300 + 90 minutes) is starting to appear; `dm-emulator` still fails at once (`DM-EMULATOR-FAIL: API 29: not run` — no KVM). By timeouts, the eight scheduled workflows can take ≈ 8 000 runner-minutes a day (≈ 33 h per runner).

**Verdict: CORRECTS.** §13.2 listed the load by timeouts and asked S0 to measure it. Measured: days without pushes use a fifth of the runners; development days saturate them (87–97 %), mostly with push-triggered gates, and scheduled work queues behind that for up to a day; scheduled runs start in the owner's morning, not at night. Three more gates (one a 60-client, 56-day world with real OpenMLS), fuzzing and weekly vendor tests do not fit "nightly"; the lever is when and how often the heavy gates run, not only T2's seed count.

**Correction S0-14 (folded: §12 L-3, §12.3, §12.10, §13.2, §14 closure blockers, §15 item 8, R-7, Q20, E-35).** §13.2's runner budget records the load by trigger; `channel-exit-gate` and `channel-privacy-gate` run **on dispatch at owner-chosen hours and weekly** (on different days), never on push; `channel-state-models` on pull requests that touch the arbitration code, weekly and on dispatch; `mls-fuzz` weekly and on dispatch against a **target-hour budget** (§15 item 8: at least 42 target-hours); `mls-vendor-tests` weekly and on pin changes; R-7 "certain"; §14's closure blockers state the calendar (weeks, not nights); **Q20 re-asked** with the options on the existing push triggers (keep; path-filter or move `t2-exit-gate` and the entitlement shards to dispatch and weekly with a light push smoke; rotate T2's seed pairs). *Effort:* 0.5 day (S10, S11).

---

## 15. Not run on this host, and why

| Item | Why not here | Where it is closed |
|---|---|---|
| V10-10 on a low-end Android device, and any arm64 execution | no device is attached to this host; the emulator images are x86_64; the arm64 `device_probe` was built but cannot run here | the owner's device step on two arm64 phones (Q20, §12.11), running the S2 successor of `device_probe`, at S2's exit if a phone is available |
| Timings that bound anything | the host ran at 100 % CPU (other builds) during every timing; the emulator shares that host | the device step |
| The emulator on API 35 | the `ghost-dm-api35` AVD was in use by another session (emulator-5576) and was not touched; API 29 was used | S12's emulator smoke on the runner or the local fallback |
| KVM runner, CI jobs, staging relays (T1 captures), the external review | not S0's: staging and the review are release gates, CI restoration is Q20; V10-14 reads the CI history instead of running jobs | Q20, §12.12, §15 item 13 |
| The 105 WG vectors of suites 0x0002, 0x0004 … 0x0007 | the libcrux provider implements none of those suites | not applicable to GHOST (S0-13) |
| A Linux host (JVM worlds, `ghost-dm-host` with MLS) | the spike does not build the host JNI library; the JVM side is S2's | S2 (`ghost-dm-host` exports `MlsNative`) |
| The per-epoch split of S0-6 under crash enumeration and golden upgrade tests | spike code only; measured for size, CPU, reassembly (byte-identical) and late-post behaviour | S2 (G-M7 golden, reload oracle, SCN-CH) |
| A populated 100-member tree under leaf inflation | an 18-minute populate at value semantics; the blank series makes the point | S5's MM-38 killer |

(OpenMLS's own suite with every ciphersuite, listed here in the first run, **ran in the review pass**: §12.)

**R-8, run in the review pass (S0-18).** The design's R-8 assigned to S0 a re-run of the Phase 9 suites the channel engine depends on; the first run had not done it. On this host, at `b05fd85`, with JDK 17.0.20.1 and `ghost-dm-host` built from the tree (`cargo build -p ghost-dm-host --release --locked --features provenance`) and passed to the tests as `-Dghost.dm.native`: the JVM unit tests of `:crypto-bridge` (**63**) and `:messaging` (**287**, among them the DM worlds, the crash enumeration and the privacy mutants; 92 minutes of test time) executed and passed; `:storage` (**187**) and `:sync` (**328**), which Gradle first restored from its build cache, were then re-executed with `--rerun` and passed. **865 tests, 0 failures, 0 skipped.** No Phase 9 defect surfaced; Phase 9's own exit gate stays open (R-8, Q39).

---

## Appendix A. SRLabs report v1.2, re-read (E-25)

The design (Appendix C, E-25) asked S0 to re-read the report rather than rely on summaries. Read in full on 2026-09-25 (`openmls-srlabs` PDF, **42 pages** (`/Count 42`; the first run said 41), SHA-256 `791eec15…c38647`, the text extraction of the Phase 9 research):
- **Scope:** OpenMLS crates; the crypto providers "out of scope" (the differential fuzzer covered 46.81 % of the libcrux backend); the PQ suites not covered.
- **Findings:** S3-7 (high, MAC verification accepts truncated/empty tags, mitigated), S2-5, S2-2, S2-6 (medium, mitigated), S1-4 (low, mitigated), **S1-3** (low, *Acknowledged*): state-changing functions are not atomic when the storage provider fails — the report names `merge_pending_commit()`, `commit_to_pending_proposals()`, `process_message()` and `propose_self_update()`; OpenMLS's comment leaves atomicity to the application ("e.g. via a Sqlite transaction"). §3.4's change-set answers it; V10-5 and V10-12 exercised it. **S0-1** (info, *Risk Accepted*): unbounded allocations through a `LeafNodePayload`'s unknown extension, "by creating a KeyPackage **or LeafNode** objects with extremely large unknown extensions" (50 MiB made tree operations take 4.03 s); OpenMLS's comment: applications should check the sizes of incoming payloads. V10-4 showed the LeafNode half of this vector is reachable in GHOST through members' own self-updates within the blob limit; S0-5 closes it by canonical leaves.
- The design's citations of S1-3 and S0-1 (§3.1, §3.7, §6.2.4) are accurate; S0-1's "Risk Accepted" status is confirmed; the design no longer claims the 64 KiB blob bounds it.

---

## Appendix B. Verification re-runs

**First run (2026-09-25).** After every check had run once, the quick tests were re-run from scratch on the same host (`cargo test --release -p ghost-mls-spike` without the two 100-member populate tests, and `ghost-mls-spike-kat`): all passed, and every size of §4 (the 32-member tables, the thresholds, both worst Welcomes, the leaf-inflation series), every V10-11 outcome, the V10-12 totals (252/252) and every V10-13 assertion reproduced byte for byte. The V10-6 outputs reproduced after a rebuild. The 100-member populated sizes (§4) come from one run (18.7 min).

**Review pass (2026-09-26).** Every measurement a reviewer challenged was re-run by the fix author, and the tests now assert what this document quotes: `cargo test --release -p ghost-mls-spike` (every test of `v10_04_sizes`, `v10_05_adapter`, `v10_08_bootstrap`, `v10_10_timings`, `v10_11_lifetimes`, `v10_13_ext_aad`), `--features pq --test v10_09_pq`, and `-p ghost-mls-spike-kat` (55 s): all passed. Every V10-4 test ran again after the last source change (`cargo fmt`), the 100-member populated one included (23.8 min): every size quoted in §4 reproduced byte for byte, the first run's 100-member values among them. The V10-3 builds were redone from `b05fd85` (§3), the V10-1 alternatives resolved in scratch copies (§1), V10-6 re-run with its new script (identical, same hashes), OpenMLS's suite run with `all-ciphersuites` (§12), the job history crawled again with every trigger (§14), and R-8's Phase 9 suites run with the host library (865 tests, §15). **Hygiene:** `cargo fmt --check` clean; `cargo clippy --all-targets -- -D warnings` clean for `ghost-mls-spike` (default, `pq`, `det` with the custom-backend cfg) and `ghost-mls-spike-kat`; `anti-placeholder.sh`, `no-logging.sh` and `dm-jni-surface.sh` green on the tree with the spike present. The probe patch applies cleanly to the tree (`git apply --check`), and every probe build ran in a scratch copy, never in the worktree.

---

## Appendix C. Review pass, 2026-09-26

Two adversarial reviews examined this document and the spike at `b05fd85`: an **honesty** lens (does each number and claim hold on re-run? findings H1 … H15) and a **design-impact** lens (what does each finding do to the design; is anything missing? findings I1 … I11). Neither review text was cut. Every finding was verified by the fix author — the challenged measurements re-run, the cited sources read; the reviewers' own logs and probes were read as data only. **Confirmed:** all findings, two of them in part; **rejected:** one claim inside I4; **declined:** one optional suggestion inside I2.

| # | Finding | Verdict | What changed |
|---|---|---|---|
| H1 | V10-14 counted scheduled runs only and blamed them for queues built by push-triggered runs; the 09-24 row crawled while a job was queued; the aggregation uncommitted | **confirmed** (re-crawled every trigger: the night windows by trigger reproduce, e.g. 09-20: 3 687 push of 6 018 runner-minutes; days without pushes 19–21 %, development days 87–97 %, 54–67 % push) | §14 rewritten by trigger; `v10-14-crawl.sh` and `v10-14-aggregate.awk` committed; crawl after the nights ended; S0-14 and Q20 report occupancy by trigger and offer options on the existing push triggers |
| H2 | Q40's "Arti 0.46 does not allow" pinning rusqlite back is false | **confirmed** (`tor-dirmgr` requires `>=0.36.0, <0.40.0`; the no-stub lock with `libsqlite3-sys` 0.35.0 resolves offline; SQLite 3.50.2 vs 3.51.3) | §1 gives both ways out; Q40 offers the stub or the older SQLite (with CVE-2025-7709 noted) |
| H3 | V10-4's "wide (64 leaves)" column measured a tree OpenMLS truncated; the 242 B tightest margin is wrong | **confirmed** (re-measured: 64 leaves 3 145 / 3 821 / 4 213 / 3 780; 128 leaves 3 180 / **3 856 (172)** / 4 248 / 3 815; PCS 3 255, context 3 723) | §4's table by width; `v10_04_wide_trees_at_the_small_cap` asserts it; §0.2, S0-4's golden gate and the design's §5.7 use 172 B at 128 leaves; "the worst shape" includes width |
| H4 | V10-5's timings were single measurements on a loaded host (141.5 vs 708.0 ms for one configuration; 17.1 ms vs V10-10's 3.85 ms) | **confirmed** | medians of 9 with rayon at one worker; Q18 and R-3 quote medians (a received post 2.6 ms at 100 members with 2 retained, not 17–30); the bytes (reproduced within 1 %) carry the argument |
| H5 | V10-3's bytes did not reproduce from the committed tree (spike sources edited after the builds) | **confirmed** (rebuilt from `b05fd85`: 20 419 800 / 22 435 784, as the reviewer found) | §3's table from the committed tree; x86_64 headroom 229 344 B (7.3 %); S2 re-measures with the real crate; T12 checked |
| H6 | V10-10's "first run between 0.4 and 1.0 times" was false and hid a retention effect | **confirmed** (the logs give 0.32–6.81; re-measured: calls on an existing member 1.2–16.5 times slower with ≈ 20 retained epochs than with 2) | §10 states the ratios and the effect; `v10_10_retention_effect_20_populated` |
| H7 | V10-4 prescribed re-asking Q3 when a single Add exceeds the floor; the document switched to canonical KeyPackages and did not re-ask | **confirmed** (and at 128 leaves a 1 024 B Add fits only to 26 members, measured) | Q3 re-asked with both options: canonical at 32 (default) or 1 024 B at 26 |
| H8 | V10-12's reload oracle ran only its fingerprint half; the KAT test had no assertion | **confirmed** | §12 names the half that ran and where the behavioural half runs; the KAT asserts every total |
| H9 | V10-9's "the WG code points work" overstated: one KEM for all three, `supports()` ignores the KEM | **confirmed** | §9's wording; the test asserts the KEM mapping; S0-10, §4.4 |
| H10 | V10-4's worst Welcomes were batch Welcomes; "three in a populated tree" unmeasured | **confirmed** (one joiner: 27 696 B over 30 inflated leaves, 87 536 B over 98) | §4 relabelled; the populated claim withdrawn; `v10_04_welcome_worst_case_one_joiner` |
| H11 | S0-2's list incomplete (libcrux-ecdh, -sha3, -secrets, -intrinsics, the `libcrux-aesgcm` entries); repositories moved to `celabshq/` | **confirmed** (all fixed at the locked versions) | §2's complete list; the GHSA watch targets `celabshq/*` and RustSec by former names; F-11 |
| H12 | getrandom 0.2.17 is in the host graph (KAT crate); the G-R2 check needs `-e normal,no-proc-macro`; `det_world` expires | **confirmed and refined** (0.2.17 reaches the KAT crate through `openmls/test-utils` → `openmls_rust_crypto` as well as the proc-macro; `ghost-dm-host`'s linked graph has 0.4.3 only) | §6; S0-7 (c) names the host library's graph and the flag; `GHOST_SPIKE_DAY` and a window guard in `det_world` |
| H13 | Most evidence tests had no assertion; no golden size asserted | **confirmed** | `v10_04` (golden sizes, canonical KeyPackage), `v10_05` (methods, change-set growth, split), `v10_08`, `v10_09`, `v10_11` and the KAT now assert; `v10_10` stays print-only (timings bound nothing) |
| H14 | "No copyleft" with three MPL-2.0 crates | **confirmed** | "no strong copyleft; three MPL-2.0 crates (file-level)" in §0.1, §1 and the design's §3.9 |
| H15 | Nits: a missing script, README omissions, unregenerable arm64 symbol figures, 41 vs 42 pages, "median 104" of two runs, a 100 → 101 Add, a two-joiner Welcome in a one-joiner range | **confirmed** | `scripts/v10-06-determinism.sh` added; README lists every script; `v10-03-symbols.sh` regenerates both ABIs; 42 pages; the three `messaging-exit-gate` runs listed; the large class's Add 99 → 100 (9 391 / 10 020 B); the one-joiner range 25 894–26 523 B |
| I1 | V10-8: "authenticated by the GroupInfo signature" not established; a forged Welcome can capture a joiner | **confirmed by a new test** (OpenMLS accepts two forgeries; an applied one consumes the KeyPackage; the real Welcome then fails with `NoMatchingKeyPackage`) | V10-8 CORRECTS; S0-15 (the committers anchor) folded into §5.4, §5.9, §6.2.5, CO-2, CO-5, T39, JN FAKE_WELCOME, PC-19, MM-41, R-20, Q41, L8-C25, ADR-43; routed to the protocol lens |
| I2 | S0-12 still lets a committer split honest members by device clock | **confirmed** (the rule consulted the trusted day only when OpenMLS refused); its optional monotonic `commit_minute` **declined** (a forward-dated commit would freeze honest admissions through CO-2 (A)'s window) | S0-12: one trusted-day predicate on both branches, thresholds that never split honest commits, the malicious-committer split declared (L8-C20), T41 and CS-C3 qualified, EM-3 adversaries, MM-40 |
| I3 | §19 wins over earlier sections, and S0-9 and S0-13 did not edit it | **confirmed** | the fold-in edits §19.4, §19.10, §19.16, §19.18, §19.23, §19.25 in place and adds §19.26, which wins over §19.1 … §19.25 |
| I4 | V10-14 read against cron times GitHub does not honour; queue waits include the laptop being off; the DM gates' "two minutes" stale; seven fuzz nights | **confirmed in part**: cron + 275–340 minutes, 89.4 % of *scheduled* runner-minutes in 07–20 UTC (65.5 % over every trigger), the T32 jobs' 28–43 minutes; **rejected**: "about 1 320 minutes queued with no runner active" — with every trigger crawled, one minute in nine days | channel gates on dispatch at owner-chosen hours and weekly; fuzzing by target-hours; §14's calendar in weeks; L-3 restated |
| I5 | V10-5 consequences: literals of the cap; `mls_kv` WITHOUT ROWID; two per-post costs; per-call reloads under one actor; sequencing of Q18; cite R1/R2 | **confirmed** (all six; R1 and R2 re-run, now tests) | every literal of the cap; `mls_kv` a rowid table; one reconciled per-post cost; S0-17's batched calls and cache seam; the arm64 probe at S2's exit; §5 cites the re-runs |
| I6 | S0 obligations outside the §14 row: R-8's suites, the G-R/G-M pairs, seed and mutant counts, Appendix C statuses, §17 questions | **confirmed** | S0-18: R-8's suites re-run (865 JVM tests of `:storage`, `:sync`, `:crypto-bridge` and `:messaging` with the host library, all passed, §15); the pairs built once generically; counts pinned at the S10/S11 exits; Appendix C updated (E-19 … E-25, E-30 verified or measured, E-22 stays assumed); §17's S0 status line (Q16, Q22, Q26 re-asked) |
| I7 | §5.7's deferral order can produce an invalid commit; S0-5 left the 64 KiB claims; canonical leaves' consequences unstated; precision of S0-4 | **confirmed** (the unit Remove + context change measured at 3 578–3 648 B) | S0-16; §3.7, §5.7, §6.2.4 no longer claim the blob bounds S0-1; §3.8, R-2, ADR-40 and §4.4 state the frozen shape; one definition of the canonical KeyPackage (with `GhostKpBind.day = d`, the empty proposals list, the size following from RFC 9420's encoding) |
| I8 | V10-12 tests the adapter, not GHOST's join path; 0x0003 coverage thin; `all-ciphersuites` works | **confirmed** (21 vectors, 26 epochs at 0x0003; the suite run: 1 134 passed, 213 at 0x0003 with libcrux) | §12, the design's §10.1 and §12.2 state what the replay proves; Q22 re-asked; §15's row closed |
| I9 | Effort bookkeeping inconsistent | **confirmed** | §0.3's effort restated per slice (+6.25 days, 40.75 in all) and folded into §14 |
| I10 | V10-1: the KAT crate as a workspace member adds 53 packages, not 40; the stub's licence; §13.3's contradiction | **confirmed** (13 extra, measured online; `cargo deny` green) | §1; the stub under GHOST's licence; §13.3's rows |
| I11 | V10-3: x86_64 headroom, per-ABI enforcement, ADR-40, T12, the 16 000-byte post | **confirmed** (the post: 16 198 B, margin 118) | per-ABI budget and S2 re-measure; ADR-40's consequences; T12 checked; the post pinned in G-M7 |

**Disclosure carried from the honesty review.** That reviewer reported that one of its requests to crates.io carried the owner's e-mail address in its User-Agent header by mistake, and that every later request used a generic header. The fix author's requests went to crates.io only through Cargo and to GitHub only through the authenticated `gh` client.
