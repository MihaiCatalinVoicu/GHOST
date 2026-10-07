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
for g in anti-placeholder no-logging issuer-output monero-pin manifest-lint dependency-allowlist proto-check sync-no-catch-all kotlin-clearnet no-public-binaries dm-jni-surface dm-no-fts dm-enqueue-callers ch-enqueue-callers apk-no-debug-hooks workflow-yaml messaging-no-network dm-no-replace dm-derivation-inputs ch-derivation-inputs mls-jni-surface media-crate-purity; do
  bash "$DIR/$g.sh" || rc=1
done
exit $rc
