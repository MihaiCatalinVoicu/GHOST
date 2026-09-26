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
for g in anti-placeholder no-logging issuer-output monero-pin manifest-lint dependency-allowlist proto-check sync-no-catch-all kotlin-clearnet no-public-binaries dm-jni-surface dm-no-fts dm-enqueue-callers apk-no-debug-hooks workflow-yaml messaging-no-network dm-no-replace; do
  bash "$DIR/$g.sh" || rc=1
done
exit $rc
