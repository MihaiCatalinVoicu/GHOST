#!/usr/bin/env bash
# Runs every static gate (fast; no SDK required). Build-dependent gates run in their own CI jobs.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rc=0
# merged-manifest-lint.sh (T15m) needs the release build; the CI android job runs it after the build.
# The licence gates that read build outputs run where those exist (Phase 9 design §22.8.10 point 10):
# license-notices.sh rust, rust-license-headers.sh (G-R5) and mpl-sources.sh (G-L4) in the rust job
# (rust-gates.sh); license-notices.sh android (G-L1, G-L2) and apk-notices.sh (G-L3) in the android job.
# dm-jni-surface (G-R6) runs here without a library argument: the source halves of the closed list
# need no toolchain. The CI android job runs it again with the built ghost-dm-host, which adds the
# symbol check (Phase 9 design §2.6).
# dm-no-fts (G-DM6, Phase 9 design §13.6 R-M4) reads production sources as text and needs no SDK.
# dm-enqueue-callers (G-DM2, Phase 9 design §16.1, §21.7, §21.9) is the static half of T28 and T31;
# it reads the DM modules' production sources as text and needs no SDK either.
# apk-no-debug-hooks (G-DM5, Phase 9 design §16.1; slice S12) runs its source-set half here; the CI
# android job runs it again with the release build's R8 mapping.txt, which adds the mapping half.
# workflow-yaml parses every .github/workflow file: a workflow that is not valid YAML never starts, and
# nothing else in this list reads one (slice note: the DM exit gate did not run on three merges).
# The S0′ gate slice (Phase 9 design §16.1, §22.33) adds the source-only DM gates: messaging-no-network
# (G-DM1) and dm-no-replace (G-DM4); sync-no-catch-all now reads the DM modules too. Its build-dependent
# gates run where the build is: libcrux-portable (G-R3) after the native and host builds in their CI
# jobs, dm-rust-no-logging (G-R4), dm-golden-lock (G-R7) and dm-vendored-clock-log (G-R8) in the rust
# job and in rust-gates.sh.
# dm-derivation-inputs is G-DM3's Kotlin half (design §22.33 item 17: the motivated allowlist, the
# default pending the owner's word); its Rust half is a unit test of ghost-client-dm, run by cargo test.
# ch-derivation-inputs is G-M3's script half (Phase 10 design faza10-forum.md §5.2 rule (1), §13.1;
# slice S2a): the channel crate's derivations take typed secret inputs, HKDF and the MLS exporter stay
# in their modules, and no Android string looks like a channel label; it reads sources only. Its Rust
# half is ghost-client-mls's derive test. The other channel gates need cargo: G-M1 and G-M2 are clauses
# of rust-client-allowlist.sh and rust-feature-policy.sh, G-M4 and G-M8 run in rust-gates.sh and the CI
# rust job, G-M9 wherever a build's messages are read.
# mls-jni-surface is G-M6 (Phase 10 design §10.2, §13.1; slice S2b), G-R6's method for the channel
# surface `MlsNative`: its source halves run here without a library; the CI android-native job runs it
# with the shipped libraries and the android job with the ghost-dm-host build (`--test`).
# media-crate-purity is G-M7's source half (Phase 11 design faza11-media.md §13.1, §16.1 G-M7; slice
# S1): the media crate has no clock, I/O, state (but the test registry), randomness, unsafe code, JNI,
# external crate or feature; it reads sources and the manifest only. G-M7's graph halves need cargo:
# clauses of rust-client-allowlist.sh (G-R1) and rust-feature-policy.sh (G-R2), media-rust-no-logging
# (G-R4) and media-vendored-clock-log (G-R8) in rust-gates.sh and the CI rust job, and the licence scan
# (G-R5) with the client-net graph of licenses/graphs.txt.
# ch-enqueue-callers is G-M5 (Phase 10 design §13.1, §7.7; slice S4), the channel engine's G-DM2: each
# channel step makes only the relay-visible calls of its row, CH-RECV and CH-JOIN none. It reads sources only.
# Phase 11 slice S7's source gates (faza11-media.md §16.1): media-no-plaintext-io is G-M1 (no plaintext
# media at rest: the sink list and the writer allowlist), media3-dependency-allowlist is G-M2 (the
# Media3 artifact allowlist), media-decoder-confinement is G-M3's source and configuration halves (the
# decoder APIs only in org.ghost.media.sandbox; every Media3 instance built with GHOST's factories).
# G-M3's bytecode half (javap over the release variant's classes) runs in the CI android job, as do
# G-M4's merged-manifest half (merged-manifest-lint.sh) and G-M10 (media-release-dex.sh) — both need
# the release build, like T15m. G-M4's source-manifest and binding halves live in manifest-lint.sh.
# Phase 11 slice S9's G-M8 (media-golden-lock.sh): the Media3 pin's golden directory and sums; its
# bump drill (the walker's golden tests over the new pin) runs in the CI rust job at a pin change,
# as for G-R7. G-M9 (media-report-check.sh) checks the gate jobs' reports and is invoked by
# scripts/ci/media-exit-gate.sh and media-emulator.sh, not here.
# Phase 12 slice S3's static PT gates (design faza12-transports.md §13): pt-source-pin is G-T1
# (the pins' internal consistency, the patch hash, the licence note, no second hash copies);
# pt-exec-site is G-T6 (no spawn primitive on the production path; PT imports stay in
# :network/:sync); pt-no-bridge-line-in-logs is G-T7 (no logging in :network/:sync at all, and
# the PT fixtures' logs carry no bridge line); pt-refusals is G-T8 (the grammar table and the
# PT-requires-binary pins in source). The build-dependent PT gates run where their inputs are:
# pt-size (G-T3) and apk-pt-assets (G-T4) in the CI android job beside apk-native-libs, and
# pt-double-build (G-T2) in the dispatch/weekly pt-loopback job (it re-runs BUILD.sh).
# Phase 13 slice S0b's UI gates (design faza13-ux.md §13.1): G-U1 ui-secure-window (T10: every
# window secure, every activity a SecureActivity); G-U2 ui-text-protection (T24: no selection,
# share, drag, linkify, process text; the clipboard only in SensitiveClipboard/GhostRoot); G-U3
# ui-sensitive-text (the SensitiveText unwrap site); G-U4 ui-input (one text field, the menu
# filter, the IME interceptor in GhostRoot); G-U5 ui-isolation (:ui isolated; the :app traffic
# list confined to the allowlist); G-U6 ui-no-persist (T54); G-U7 ui-deps (denylist, test-only
# groups); G-U8 ui-claims (the register, T56); G-U9 ui-coroutines (the suspend/coroutines ban on
# every module except :ui and :app's org.ghost.app.ui); G-U10 ui-notifications (T11: one
# constant notification); G-U12 ui-l10n (Q9: ro/en parity). G-U11 is ui-manifest, build-dependent
# like merged-manifest-lint: it runs in the android job, not here.
for g in ui-secure-window ui-text-protection ui-sensitive-text ui-input ui-isolation ui-no-persist ui-deps ui-claims ui-coroutines ui-notifications ui-l10n; do
  bash "$DIR/$g.sh" || rc=1
done
for g in anti-placeholder no-logging issuer-output monero-pin manifest-lint dependency-allowlist proto-check sync-no-catch-all kotlin-clearnet no-public-binaries dm-jni-surface dm-no-fts dm-enqueue-callers ch-enqueue-callers apk-no-debug-hooks workflow-yaml messaging-no-network dm-no-replace dm-derivation-inputs ch-derivation-inputs mls-jni-surface media-crate-purity media-no-plaintext-io media3-dependency-allowlist media-decoder-confinement media-golden-lock builder-pins pt-source-pin pt-exec-site pt-no-bridge-line-in-logs pt-refusals; do
  bash "$DIR/$g.sh" || rc=1
done
exit $rc
