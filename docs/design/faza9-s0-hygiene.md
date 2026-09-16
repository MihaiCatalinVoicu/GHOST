# GHOST Phase 9, slice S0′: repository hygiene and licences (evidence)

| Field | Value |
|---|---|
| Slice | S0′ of `docs/design/faza9-dm.md` §17.1, the hygiene and licence part (the owner preconditions recorded, CI artifacts, `org.signal`, the licence gates, the ADRs, the question defaults); the spikes and measurement probes V-1 … V-17 are separate work |
| Normative input | `faza9-dm.md` §0, §2.10, §16, §17.1 row S0′, §19, §21.13, §22, §22.8.9 … §22.8.11, Appendix A, Appendix B.6 (precedence §22.8 > §22 > §21 > §0–§20) |
| Date | 2026-09-16 |
| Branch | `p9-hygiene` (from `main` at `cc24c5c`) |

## 1. Public horizon (§22.8.9 point 1; ADR-39 point 1)

| Fact | Value | How it was checked |
|---|---|---|
| Visibility now | `private` (`"private": true, "visibility": "private"`, `pushed_at` 2026-09-16T18:01:46Z) | `gh api repos/MihaiCatalinVoicu/GHOST` at 2026-09-16T18:13:09Z |
| Last public SHA | **`3edf9dd0b2b20d7e4061b5028801d455f0268648`** ("Phase 9 design revised: no libsignal, closed source (owner decision 2026-09-16)", committed 2026-09-16T16:10:36+03:00), the last push while the repository was public (owner statement) | `git log`; it is an ancestor of `main` |
| Public history | the 118 commits reachable from `3edf9dd` (`git rev-list --count 3edf9dd`): `b2df181` and everything older, plus `57d347e`, `e267b3f` and `3edf9dd` after `b2df181` | `git merge-base --is-ancestor b2df181 3edf9dd`; `git log b2df181..3edf9dd` |

Everything in that history is public for good (ADR-39 point 1): code of Phases 0–8, every design (including the libsignal-era Phase 9 rounds), THREAT_MODEL, LIMITE, runbooks, staging onion addresses, commit metadata, and the `MIT OR Apache-2.0` declaration of `ghost/Cargo.toml` up to that commit. No history rewrite. Counsel's review of that set (ADR-37 point 10, R-39) and the staging onion key rotation (ADR-39 point 5, if those relays serve beyond staging) remain owner actions.

## 2. Actions artifact inventory (counts and date ranges only)

`gh api --paginate repos/MihaiCatalinVoicu/GHOST/actions/artifacts` at 2026-09-16T18:13:09Z: **348 artifacts, none expired**, created 2026-09-10T08:58:23Z … 2026-09-16T17:57:56Z. Classified by the head commit of the run that uploaded them (an ancestor of `3edf9dd` or `3edf9dd` itself: "public history"):

| Kind (artifact name) | Public history: count, created, expires | Later commits (`ci/self-hosted`): count, created, expires |
|---|---|---|
| `app-release-unsigned` (APK) | **37**, 2026-09-10T08:58:23Z … 2026-09-16T13:26:56Z, until 2026-12-09 … 2026-12-15 | 0 |
| `ghost-client-net-jniLibs` (native libraries) | **33**, 2026-09-10T11:58:56Z … 2026-09-16T13:25:26Z, until 2026-12-09 … 2026-12-15 | 2, 2026-09-16T15:00:58Z … 15:18:37Z, until 2026-09-19 |
| `entitlement-exit-gate-N` (reports) | 204, 2026-09-13T11:32:41Z … 2026-09-16T13:48:12Z, until 2026-12-12 … 2026-12-15 | 13, 2026-09-16T15:04:57Z … 17:01:34Z, until 2026-09-19 |
| `t2-exit-gate-N` (reports) | 41, 2026-09-14T00:13:18Z … 2026-09-16T15:12:39Z, until 2026-12-12 … 2026-12-15 | 1, 2026-09-16T17:57:56Z, until 2026-09-19 |
| `t2-mutants` (reports) | 14, 2026-09-13T23:56:07Z … 2026-09-16T14:49:26Z, until 2026-12-12 … 2026-12-15 | 1, 2026-09-16T16:37:04Z, until 2026-09-19 |
| `sync-exit-gate-reports` (reports) | 2, 2026-09-11T18:52:50Z … 2026-09-13T11:57:48Z, until 2026-12-10 … 2026-12-12 | 0 |
| **Total** | **331** (329 from `main`, 2 from `p8/t2-gate`), 2026-09-10T08:58:23Z … 2026-09-16T15:12:39Z | **17**, 2026-09-16T15:00:58Z … 17:57:56Z |

The design counted 299 artifacts earlier the same day (§22.8.9 point 1); the runs since account for the difference. **No artifact was deleted:** deleting the public-era artifacts, first the 37 APK and 33 native-library ones, is the owner's action (ADR-39 point 2, §22.8.9 point 2 (a), Q62) and is still open.

## 3. CI: hand-off retention and no public binaries (§16.2, §22.8.9 point 3; ADR-39)

- **`ghost-client-net-jniLibs` is kept 1 day** (`.github/workflows/ci.yml`; the self-hosted change had set 3). One day is safe: the hand-off is internal to a run (`android-native` uploads, `android` and `reproducible` download it through `needs:`), and a complete `ci` run took 1 h 55 min on the four self-hosted runners with all five workflows competing (`docs/ci-self-hosted.md` §8). A run left queued for more than a day (runners offline) fails closed at the download; "Re-run all jobs" rebuilds the hand-off, while "Re-run failed jobs" cannot (written in `docs/ci-self-hosted.md` §6). Storage: 15 600 339 B per hand-off (§22.8.9 point 1); with 1-day retention only the last day's runs count against the 500 MB artifact storage of GitHub Free, which self-hosted runners do not change (minutes are not billed for them, artifact storage is).
- **Gate evidence** (text reports: `entitlement-exit-gate-N`, `t2-exit-gate-N`, `t2-views-N`, `t2-mutants`, `sync-exit-gate-reports`) stays at 3 days, inside §16.2's 1–7.
- **No APK upload** (`app-release-unsigned` was removed by the self-hosted change set).
- **Gate G-L5** `ghost/scripts/gates/no-public-binaries.sh` (in `run-all.sh`, job `static-gates`): the visibility is declared in `ghost/scripts/gates/repository-visibility.txt` (`private`) and, in GitHub Actions, compared with the event payload's `repository.private`; every `upload-artifact` sets `retention-days` 1–7; a binary upload (APK, AAB, AAR, DEX, JAR, `.so`, `jniLibs`, Gradle apk/bundle/aar outputs, disk or container images) is refused while the repository is not declared private, and in a private repository only the named internal hand-off with `retention-days: 1` and a download in the same workflow passes; releases, Pages, registry pushes and Gradle or Cargo publication fail in any workflow. Fixtures: `ghost/test-harness/gates/no-public-binaries/` (11 cases, README there).

## 4. `org.signal` (§2.10.2, §16.1; ADR-37 point 5)

Removed from `ghost/android/gradle/libs.versions.toml` (the `libsignal = "0.86.5"` version and the `libsignal-android` alias) and from `ghost/scripts/gates/dependency-allowlist.txt`; added to `dependency-denylist.txt`. `verification-metadata.xml` held no `org.signal` entry. Fixture: a `libsignal-android` line in `test-harness/gates/negative/android/gradle/libs.versions.toml`; `self-test.sh` requires "DENIED dependency group 'org.signal'". `ghost/deny.toml` names the 14 crates of §22.8.10 point 1 by exact name; `self-test.sh` builds a scratch lock file for each (a local crate of that name) and requires "crate '<name> = 0.1.0' is explicitly banned" and "bans FAILED", and "bans ok" for an unbanned name (the `rust` job installs `cargo-deny` 0.20.2 and sets `GHOST_SELFTEST_DENY`). `cargo deny check bans licenses sources` stays green on the workspace.

## 5. Licence gates (§2.10.2, §16.1, §22.8.10 points 1–3, 10)

| Gate | Script / file | CI | Rule as implemented | Negative fixtures (`self-test.sh`) |
|---|---|---|---|---|
| G-L1 (Rust) | `license-notices.sh rust` | `rust` (and `rust-gates.sh`) | regenerates `ghost/licenses/THIRD_PARTY_NOTICES-{client-net,relay,issuer}.txt` for the graphs of `ghost/licenses/graphs.txt` and fails on a difference, a licence without a resolvable text, an Apache-2.0 component without an upstream NOTICE snapshot entry, a dropped NOTICE, an undecided licence file of vendored sources, a committed notices file of an unknown graph | differs, no text, dropped NOTICE, no snapshot entry, undecided vendored licence, copyleft-only package; positive case also checks that the NOTICE and the vendored licence are carried and the unused alternative is not |
| G-L1 (Gradle) and G-L2 | `license-notices.sh android <components>`; `gradle-license-allowlist.txt` | `android`, after the build | `./gradlew :app:releaseRuntimeComponents` lists the external components of the release runtime classpath with their classes jar; each needs a `group:artifact SPDX` line, a licence of the `deny.toml` allow list without MPL-2.0 (ADR-37 point 2), and a POM (parents followed) whose licence maps to that SPDX id; stale lines fail; texts from `META-INF` licence and notice files of the jar, the upstream snapshot, or SPDX; regenerates `THIRD_PARTY_NOTICES-android.txt` and compares | missing allowlist line, copyleft licence, POM declaring another licence, stale line; positive case (a Gradle cache, POM and jar built at test time) |
| G-L3 | `apk-notices.sh <apk>` | `android` and `reproducible-build.sh` | the APK has `assets/THIRD_PARTY_NOTICES.txt` whose SHA-256 equals preamble + Gradle part + client-net part | changed asset, missing asset; positive case |
| G-L4 | `mpl-sources.sh [--bundle <dir>]`; `ghost/licenses/mpl-sources.txt` | `rust` (with `--bundle $RUNNER_TEMP/mpl-sources`) | the manifest lists exactly the packages used under MPL-2.0 with their Cargo.lock SHA-256; a `[patch]` of one needs `ghost/licenses/mpl-patches/<crate>-<version>.diff`; `--bundle` copies the checked `.crate` archives (the release source bundle) | missing line, wrong checksum, stale line, `[patch]` without diff; positive and bundle cases |
| G-L5 | `no-public-binaries.sh` | `static-gates` | §3 | 11 cases |
| G-R5 | `rust-license-headers.sh`; `rust-license-exceptions.txt` | `rust` | over the packages of `cargo tree -e normal --target <shipped triples>` (and GHOST's own crates of those graphs): SPDX expressions parse and have an allowed alternative; a file fails when it declares a GNU licence (an `SPDX-License-Identifier` with GPL, LGPL or AGPL; the "under the terms of the GNU … General Public License" notice across comment lines; a GNU licence text) or carries a "Signal Messenger" copyright; reviewed exceptions (crate, version, file or `*`, reason); an unused exception fails | AGPL header, Signal Messenger copyright, GPL notice, GPL text, no allowed alternative (5 lines reported exactly), own-crate scan with an unused exception; an excepted LGPL header passes |
| `deny.toml` bans | 14 named bans | `rust` (cargo-deny-action), self-test | §4 | 14 banned names and one control |

**Facts of the current graphs (2026-09-16).**
- Shipped Rust graphs: `ghost-client-net` for `aarch64-linux-android` and `x86_64-linux-android` (**421** third-party packages, proc-macros included), `ghost-relay-node` for `x86_64-unknown-linux-gnu` (**113**), `ghost-issuer` and `ghost-issuer-ops` for `x86_64-unknown-linux-gnu` (**136**); 443 distinct packages. The relay and issuer images build on `rust:1.98.1-bookworm` for x86_64 (`infra/*/Dockerfile`).
- **Licence choice** for packages that offer alternatives: only licences of the `deny.toml` allow list; the alternative whose texts the package ships; then MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0, Unlicense, CC0-1.0, Apache-2.0 WITH LLVM-exception, MPL-2.0. Texts of alternatives not used (LICENSE-APACHE of a package used under MIT, the LGPL text of `priority-queue`) are left out; every other licence or notice file at the package root is kept.
- **Texts from SPDX** where a package ships none (arti and tor-* crates, `amplify_num`, `amplify_syn`, `cesu8`'s MIT/Apache texts, AndroidX): SPDX License List **3.28.0** as embedded in the crates.io `spdx` crate 0.13.4 (`.crate` SHA-256 `a8da593e30beb790fc9424502eb898320b44e5eb30367dbda1c1edde8e2f32d7`, the licence-list data cargo-deny 0.20.2 uses), copied for the ids of the allow list plus `LLVM-exception` into `ghost/licenses/spdx/` with per-text SHA-256 in `SOURCE.txt` (`licenses.pl spdx-snapshot` rewrites it). For such packages the notices name the Cargo `authors`.
- **Upstream NOTICE snapshot** (`ghost/licenses/upstream/`, written by `ghost/scripts/license-upstream-snapshot.sh` through the GitHub API): the 9 Rust packages used under Apache-2.0 (`amplify_derive` 4.0.1, `amplify_num` 0.5.4, `amplify_syn` 2.0.1, `imara-diff` 0.2.0, `prost` 0.14.4, `prost-derive` 0.14.4, `reseeding_rng` 0.10.7, `ring` 0.17.14, `sync_wrapper` 1.0.2) have **no NOTICE file** at their published commit (`.cargo_vcs_info.json`), in the package directory or at the repository root; `ring`'s archive is marked `dirty` by cargo, the check still reads the recorded commit. Gradle: `net.zetetic:sqlcipher-android` 4.19.0 ships no licence text in its AAR; its `LICENSE` was captured at tag `v4.19.0` (commit `9a5d685404489cbff14d4c46da81555de1a38787`). Every other Gradle component's text is the SPDX Apache-2.0 text, the AndroidX `META-INF/.../LICENSE.txt` files, or BouncyCastle's `META-INF/LICENSE.md`.
- **Vendored sources** (`ghost/licenses/vendored-licences.txt`, 13 decisions): the licence files of xz in `liblzma-sys` (0BSD kept; the GPL and LGPL texts of the tools, scripts and getopt, which `build.rs` does not compile, left out), `zstd-sys` (BSD kept, GPL-2.0 alternative left out), `regex-syntax` (Unicode data), `ring` (once_cell polyfill under MIT, fiat-crypto), `tracing-core` (spin); `libsqlite3-sys`'s `sqlcipher/LICENSE` is left out because the `bundled` feature compiles SQLite, not the vendored SQLCipher.
- **G-R5 findings and exceptions:** `priority-queue` 2.7.0 (`*`: LGPL text and headers of the unused alternative; MPL-2.0 used), `zstd-sys` 2.1.0+zstd.1.5.7 `zstd/COPYING` (GPL-2.0 alternative), 19 files of `liblzma-sys` 0.4.8 (xz scripts, getopt, build files, GPL/LGPL texts; `build.rs` compiles only `xz/src/liblzma` and two `xz/src/common` files). No AGPL header and no Signal Messenger copyright in any shipped package or GHOST crate.
- **MPL-2.0:** `option-ext` 0.2.0 and `priority-queue` 2.7.0, both in the `ghost-client-net` graph only; the client-net notices end with the source offer (crates.io download address and Cargo.lock SHA-256 of each archive; archives provided with every release).
- **Gradle release runtime classpath:** 66 components: 64 Apache-2.0, `org.bouncycastle:bcprov-jdk18on` MIT (POM "Bouncy Castle Licence"), `net.zetetic:sqlcipher-android` BSD-3-Clause (POM URL `zetetic.net/sqlcipher/license`). They include `kotlinx-coroutines` and `kotlinx-serialization-core` as transitive dependencies of AndroidX lifecycle (not used by GHOST code).
- **Notices sizes:** client-net 469 947 B (421 components, 229 distinct texts), relay 159 005 B, issuer 179 445 B, Gradle part 32 244 B; the APK asset `assets/THIRD_PARTY_NOTICES.txt` is 503 175 B. A local offline `:app:assembleRelease` built it and `apk-notices.sh` passed on that APK.
- **App wiring** (`ghost/android/app/build.gradle.kts`): task `thirdPartyNoticesAsset` concatenates `ghost/licenses/apk-notices-preamble.txt` (GHOST copyright, the part layout, the SQLCipher credit: SQLCipher for Android by Zetetic LLC, based on SQLite, with LibTomCrypt, which the AAR's `libsqlcipher.so` names), `THIRD_PARTY_NOTICES-android.txt` and `THIRD_PARTY_NOTICES-client-net.txt` into a generated assets directory of every variant; task `releaseRuntimeComponents` writes the component list. No Gradle coordinate or plugin was added.

## 6. ADRs filed (Appendix A, §16.4 list, B.6)

`docs/adr/ADR-30-dm-blind-addressing.md` (ADR-30′), `ADR-31-dm-envelope-sealed-sender.md` (ADR-31′), `ADR-32-dm-ephemeral-ttl-seconds.md` (ADR-32, unchanged by the revision), `ADR-33-dm-sessions-key-change.md` (ADR-33′), `ADR-34-dm-sync-entitlement-schema-ci.md` (ADR-34′), `ADR-35-dm-library-vodozemac.md`, `ADR-36-dm-post-quantum.md`, `ADR-37-closed-source-licences.md`, `ADR-38-verifiability-without-source.md`, `ADR-39-private-repository.md`: the Romanian texts of Appendix A with every §21 and §22.8 correction they carry, status "Propus 2026-09-16, aplicat în Faza 9" (owner decision pending, Q4), the source row naming `docs/design/faza9-dm.md`. ADR-37 and ADR-39 gained a section recording what S0′ applied and found (§1–§5 of this file). `docs/adr/README.md`: section "Propuse (aplicate în Faza 9)" and section "Retrase" with ADR-28 and ADR-29 (withdrawn 2026-09-16, numbers not reused). ADR-07: status "revizuit parțial de ADR-37 și ADR-38" (closed source; T12, the signed manifest, the onion mirror and anti-rollback stay) and a revision section; its README row says so. The ADR-05, ADR-12 and ADR-17 notes of B.1/B.6 stay with S14.

## 7. Owner questions: defaults applied (§19; the standing instruction applies them unless the owner objects)

Removed or void: Q1 (removed), Q2, Q3, Q21 (void). Owner decisions already taken on 2026-09-16 and recorded here: the repository is private now, CI runs on self-hosted runners (instead of Q62's payment-method default), the licence is proprietary to Mihai Voicu (Q59).

| Q | Default applied |
|---|---|
| Q4 | ADR-35 … ADR-39 and ADR-30′ … ADR-34′ filed as "propus, aplicat"; ADR-28 and ADR-29 withdrawn, numbers retired |
| Q5 | GHOST four-mode seal (pair, intro with X-Wing inner layer, provisional, bundle), no certificates |
| Q6 | DM floor of 4 KiB |
| Q7 | contacting only with a card (QR or link), never from a bare `ghost1…` |
| Q8 | no receipts or typing in Phase 9; read receipts only in Phase 13, opt-in, STANDARD mode only |
| Q9 | no one-time keys through relays; weekly generations; secrets erased 91 days after supersession (L7-D11 accepted) |
| Q10 | ADR-14 attestation deferred, never in a relay-readable bundle |
| Q11 | shared weekly deposit key registered by the recipient; senders spend no tokens on foreign namespaces |
| Q12 | key change blocks both directions until acknowledgement or verification; classified only with a valid Ed25519 binding |
| Q13 | Olm identity derived from the MESSAGING branch |
| Q14 | static inbox and bundle namespaces per card (L7-D13 accepted) |
| Q15 | 30-day relay TTL for 30-day and timer-off conversations (ADR-27 unchanged) |
| Q16 | relays accept exactly the five TTL buckets; observable `ttl_bucket_seconds` |
| Q17 | one inexact alarm (non-exported receiver, no extras, no new permission) |
| Q18 | Phase 8 drop format unchanged in Phase 9 (deferred to Phase 12) |
| Q19 | notifications never show content or sender |
| Q20 | FRESH = 45 days; every DM op's store deadline capped at 7 days |
| Q22 | session-start co-occurrence declared (L7-D2); decoupling in Phase 12; no UI claim before |
| Q23 | NFR-1 measured and recorded, not claimed |
| Q24 | 70 MiB APK limit; native library reported separately |
| Q25 | local content stored as envelopes under a Keystore-wrapped content key |
| Q26 | unknown card holders' first messages shown as requests (cap 64, 7 days) |
| Q27 | cut-off (card rotation) deferred to Phase 13; block is local |
| Q28 | encrypted contact-card backup deferred to P1 |
| Q29 | errata applied in S14 (FR-4.6; plan row 9 TTL wording read as ADR-27 point 11) |
| Q30 | exit-gate evidence: JVM gates, emulator job on loopback relays, signed two-device checklist, one commit |
| Q31 | pending key registrations count as write work |
| Q32 | Invite v3 deferred to Phase 13; ADR-05's optional card stays open |
| Q33 | the statistical DM world (T32) is in the Phase 9 gate |
| Q34 | automatic identical-bytes resend of INDETERMINATE ops, at most twice |
| Q35 | the Phase 8 T2 world models DM owner namespaces and exports `keys.redb` |
| Q36 | card-holder inbox reads with its own token declared (L7-D3, L7-D16); owner-bound read rule in Phase 12 |
| Q37 | `MAX_CONTACTS = 1 000`, lowered in S7 if the hint benchmark misses its budget |
| Q38 | credentials static per (card, relay slot, kind), bound to the slot |
| Q39 | ADR-27 TTL classes kept; the pairing residue declared (L7-D4) |
| Q40 | pair-mode roots only after acknowledgement |
| Q41 | 5-minute messages share the 1-hour store deadline; never cancelled at expiry |
| Q42 | bundle fetch: at most three 15-minute attempts, then "unreachable" |
| Q43 | week-coarse `uploaded_at` for v3 reads; week-coarse expiry for FETCH reads |
| Q44 | vodozemac (Olm); OpenMLS stays the Phase 10 library and the DM fallback |
| Q45 | vodozemac 0.11.0 |
| Q46 | Olm `SessionConfig` V1 |
| Q47 | nesting (X-Wing seal around unchanged Olm 3DH) |
| Q48 | PQ-C inside Phase 9 as slice S13, not blocking the exit gate |
| Q49 | root replacement every 4 weeks |
| Q50 | no seed-derivable first-contact key |
| Q51 | binding v3 |
| Q52 | session state wrapped under a Keystore-protected state key held in native memory |
| Q53 | seal, codec, cards, bindings and safety numbers in Rust (`ghost-client-dm`) |
| Q54 | peek-ordered consumption plus a gap hold of at most 12 minutes |
| Q55 | `libcrux-kem` X-Wing, portable-only; the combiner if the S0′ graph review rejects its crates |
| Q56 | libcrux ML-KEM; aws-lc-rs documented fallback |
| Q57 | ProVerif model in CI and external review before the first distributed APK; reviewer chosen by the owner |
| Q58 | upstream contributions to vodozemac, no fork |
| Q59 | proprietary licence (owner decision), generated notices, gates G-L1 … G-L5 and G-R5 from S0′ (this slice) |
| Q60 | MPL-2.0 only unmodified with a source offer; no new MPL in the DM stack |
| Q61 | the verifiability package as release gates (ADR-38), with the §22.8.8 additions; no partial open-sourcing now |
| Q62 | repository private and proprietary licence before any Phase 9 code (done by the owner); public artifacts to be deleted by the owner (still open, §2); CI cost: the owner chose self-hosted runners (`docs/ci-self-hosted.md`) instead of a payment method |
| Q63 | a new public repository for the specification, vectors, model and verification kit |
| Q64 | `UNACK_MAX = 28 days` |
| Q65 | PQ protection of relay RPC metadata in Phase 12 (or Tor's PQ handshake if it ships first) |
| Q66 | no post-quantum or hybrid signatures now |
| Q67 | prune skipped keys if V-15 shows the golden-pickle and `UpgradeTest` drills cover it; otherwise declare |
| Q68 | PQ-C every 4 weeks until measured; 7 days only if V-13 holds |
| Q69 | bundle-fetch visibility declared in Phase 9; relay visibility floor specified in Phase 12 |
| Q70 | first-message full card declared (L7-D25, Phase 13 copy); reduced reply card evaluated in Phase 13 |
| Q71 | onion mirror as the primary channel; Accrescent kept with the residue declared; no F-Droid-format repository until a verifier covers it |

## 8. Deviations and additions (each with its reason)

1. **Cargo licence field.** The owner's change before this slice set `license = "LicenseRef-GHOST-Proprietary"` in `ghost/Cargo.toml`, not `license-file` (§22.8.9 point 2 (c)). Kept: the SPDX `LicenseRef-` form names the same root `LICENSE`, `[licenses.private] ignore = true` makes cargo-deny skip it, and G-R5 treats GHOST's crates as own crates.
2. **`crabgrind` 0.2.6 exception not filed.** §22.8.10 point 2 names it, but it is in no shipped graph until the DM crates land (S4a); an exception that matches nothing fails G-R5, so the line joins with the crate.
3. **Licence choice prefers MIT** for dual-licensed packages (§5). The design fixes no election; with MIT, Apache-2.0 NOTICE obligations apply to the 9 packages used only under Apache-2.0, which the upstream snapshot covers.
4. **Vendored licence files** are decided explicitly (`vendored-licences.txt`): not in the design, needed because `zstd-sys`, `liblzma-sys`, `ring`, `regex-syntax` and `tracing-core` compile vendored code whose licence files are not at the package root, while `libsqlite3-sys` ships a SQLCipher licence for code it does not compile.
5. **G-R5 also scans GHOST's own crates** of the shipped graphs (an AGPL header or Signal Messenger copyright copied into GHOST code fails; ADR-37 point 9).
6. **G-L5 knows the visibility** from a committed declaration checked against the event payload (the design does not say how a static gate learns it); it also enforces §16.2's `retention-days` 1–7 on every upload and forbids publication steps.
7. **G-L2 has no script of its own:** `license-notices.sh android` enforces `gradle-license-allowlist.txt` (the design names only the file), with its own messages and fixtures; the allowlist lives next to the dependency allowlist in `ghost/scripts/gates/`.
8. **G-L4's release source bundle** does not exist before Phase 14; `mpl-sources.sh --bundle` builds it from `.crate` archives checked against Cargo.lock, and the `rust` job builds it on every run.
9. **The APK asset** is assembled at build time from committed parts (Rust part checked in `rust`, Gradle part in `android`, since neither job has the other's toolchain); G-L3 also runs inside `reproducible-build.sh`.
10. **Gate placement follows §22.8.10 point 10**; `license-notices.sh rust`, `rust-license-headers.sh` and `mpl-sources.sh` also run from `rust-gates.sh` locally. G-L1 runs `cargo fetch --locked` first, because `cargo tree` resolves target-specific packages whose sources may not be extracted.
11. **§22.8.9 point 4 (CI plan on private 2-CPU runners)** is superseded by the owner's self-hosted runners; measured durations are in `docs/ci-self-hosted.md` §8. The Phase 9 jobs' budgets are measured when those jobs exist.
12. **Not in this slice:** G-R1 … G-R8, the `rust-crypto-pins.sh` version sets (§22.8.10 point 5) and the allowlist names of the DM graph (they need the DM crates, S4a/S4b), the spikes V-1 … V-17.

## 9. Open items

- Owner: delete the public-era Actions artifacts (§2), counsel review of the public `MIT OR Apache-2.0` history (ADR-37 point 10), staging onion key rotation if applicable (ADR-39 point 5), decisions on Q4 and the other defaults.
- Before the first distribution: the in-app licence screen (Phase 13), the per-release SBOM with the notices hash (ADR-37 point 8), the ADR-38 package.
- S14: ADR-05, ADR-12, ADR-17 notes (B.1, B.6), `docs/STATUS.md` Phase 9 row, the other documents of §16.4.
- Whenever a Rust package starts being used under Apache-2.0, or a Gradle component ships no licence text, `license-notices.sh` fails until `ghost/scripts/license-upstream-snapshot.sh` (network, `gh`) records it and the result is reviewed.
