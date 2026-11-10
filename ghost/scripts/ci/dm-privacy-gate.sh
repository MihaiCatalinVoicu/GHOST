#!/usr/bin/env bash
# dm-privacy-gate.sh — the local equivalent of the legacy .github/workflows/dm-privacy-gate.yml
# (Phase 9 design §14.1 T32/T34/T35, §15.6, §15.7, §16.2; ADR-58: CI is local). Two jobs, exactly
# the workflow's steps:
#
#   worlds  — the T32 privacy world per seed-pair index (0-9, §15.6's ten pinned pairs), each run
#             against the ghost-dm-host build WITH the `provenance` feature (T35 asserts every
#             seal's key kinds at runtime, design §14.1 T35/§15.5 PQ2), then judged by
#             dm-report-check.sh … privacy-gate. Sequential locally (one workstation), resumable
#             via done-markers; the CI ran three pairs at once on memory, not speed.
#   suite   — the scale-independent half: NI-DM1/2/3, JD7 under WITHHOLD_ALL_BUNDLES, the two T34
#             seizure worlds, JD8 (+its self-test), the privacy mutants and the edge statistics
#             (+self-test) — one gradle invocation, then judged by dm-report-check.sh …
#             privacy-suite.
#   all     — worlds, then suite (the workflow's two jobs).
#
# Usage: dm-privacy-gate.sh [worlds|suite|all] [--native <ghost_dm_host library>] [--from <index>]
# Environment: JAVA_HOME/ANDROID_HOME as usual for gradlew; PROTOC must be reachable (or set) for
# the host build, as in any local cargo build of the workspace.
#
# Reports: messaging/build/reports/dm/privacy-t32-pair<i>.txt per pair and privacy-suite.txt for
# the suite, so reruns do not overwrite evidence (the CI's matrix jobs each had their own
# privacy.txt). Exit status: 0 only when every executed step and every gate judgment passed.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST="$(cd "$DIR/../../" && pwd)"            # the ghost/ directory (cargo workspace root)
ANDROID="$GHOST/android"
REPORTS="$ANDROID/messaging/build/reports/dm"
MARKERS="$REPORTS/.matrix"

cmd="all"; NATIVE=""; FROM=0
while [ $# -gt 0 ]; do
  case "$1" in
    worlds|suite|all) cmd="$1"; shift ;;
    --native) NATIVE="$2"; shift 2 ;;
    --from) FROM="$2"; shift 2 ;;
    *) echo "dm-privacy-gate: unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$cmd" in worlds|suite|all) ;; *) echo "usage: dm-privacy-gate.sh [worlds|suite|all] [--native <lib>] [--from <index>]" >&2; exit 2 ;; esac

# The provenance host build (T35): the same crate with `provenance::assert_seal` compiled in —
# the workflow's first step in both jobs. cargo clean of the libcrux crates first, exactly as CI,
# so the AES/portable check below sees a fresh build of those packages.
if [ -z "$NATIVE" ]; then
  ( cd "$GHOST" && \
    cargo clean -p libcrux-ml-kem -p libcrux-sha3 -p libcrux-intrinsics -p libcrux-aes --release 2>/dev/null || true; \
    cargo build -p ghost-dm-host --release --locked --features provenance \
      --message-format=json-render-diagnostics > "$MARKERS/dm-host-build.json" ) || \
    { echo "dm-privacy-gate: the provenance host build failed" >&2; exit 1; }
  bash "$GHOST/scripts/gates/libcrux-portable.sh" --with-aes --json "$MARKERS/dm-host-build.json" || \
    { echo "dm-privacy-gate: libcrux-portable.sh refused the host build" >&2; exit 1; }
  case "$(uname -s)" in
    *NT*|MINGW*|CYGWIN*) NATIVE="$GHOST/target/release/ghost_dm_host.dll" ;;
    *)                   NATIVE="$GHOST/target/release/libghost_dm_host.so" ;;
  esac
fi
[ -f "$NATIVE" ] || { echo "dm-privacy-gate: no host library at $NATIVE" >&2; exit 2; }

# The closed JNI surfaces of the host build (the workflow's G-R6 and G-M6 steps).
bash "$GHOST/scripts/gates/dm-jni-surface.sh" --test "$NATIVE" || exit 1
bash "$GHOST/scripts/gates/mls-jni-surface.sh" --test "$NATIVE" || exit 1

rc=0
mkdir -p "$MARKERS"

run_pair() { # index
  local i="$1" report="$REPORTS/privacy-t32-pair$i.txt"
  if [ -f "$MARKERS/pair-$i.done" ]; then
    echo "dm-privacy-gate: pair $i already done (marker $(cat "$MARKERS/pair-$i.done")), skipping"
    [ "$(cat "$MARKERS/pair-$i.done")" = 0 ] || rc=1
    return
  fi
  echo "dm-privacy-gate: pair $i (T32 world, N=600, 42 days, provenance host)"
  ( cd "$ANDROID" && ./gradlew --no-daemon :messaging:testDebugUnitTest --rerun \
      --tests 'org.ghost.messaging.dmworld.DmPrivacyWorldTest.t32JoinsAndSdm3HoldOverThePrivacyWorld' \
      -Dghost.dm.native="$NATIVE" -Dghost.dm.privacy=gate -Dghost.dm.privacy.seed="$i" \
      -Dghost.dm.heap=6g -Dghost.dm.privacy.report="$report" )
  local grc=$?
  echo "$grc" > "$MARKERS/pair-$i.done"
  if [ "$grc" -ne 0 ]; then rc=1; return; fi
  bash "$GHOST/scripts/gates/dm-report-check.sh" "$report" privacy-gate || rc=1
}

run_suite() {
  local report="$REPORTS/privacy-suite.txt"
  if [ -f "$MARKERS/suite.done" ]; then
    echo "dm-privacy-gate: suite already done (marker $(cat "$MARKERS/suite.done")), skipping"
    [ "$(cat "$MARKERS/suite.done")" = 0 ] || rc=1
    return
  fi
  echo "dm-privacy-gate: suite (NI-DM1/2/3, JD7 withhold, T34 x2, JD8, mutants, edge statistics)"
  ( cd "$ANDROID" && ./gradlew --no-daemon :messaging:testDebugUnitTest --rerun \
      --tests 'org.ghost.messaging.dmworld.DmPrivacyWorldTest.niDm1InboundContentLeavesTheRecipientsViewUnchanged' \
      --tests 'org.ghost.messaging.dmworld.DmPrivacyWorldTest.niDm2TypeAndSessionStateLeaveTheSizesUnchanged' \
      --tests 'org.ghost.messaging.dmworld.DmPrivacyWorldTest.niDm3IdleContactsLeaveTheOwnersViewUnchanged' \
      --tests 'org.ghost.messaging.dmworld.DmPrivacyWorldTest.jd7UnderWithholdAllBundlesTheAttemptsStayBounded' \
      --tests 'org.ghost.messaging.dmworld.DmPrivacyWorldTest.t34TheSeizureOpensNothingOfAnExpiredWeek' \
      --tests 'org.ghost.messaging.dmworld.DmPrivacyWorldTest.t34OneReplyBothSidesEraseTheirProvisionalKey' \
      --tests 'org.ghost.messaging.dmworld.DmJd8Test' \
      --tests 'org.ghost.messaging.entworld.Jd8SelfTest' \
      --tests 'org.ghost.messaging.dmworld.DmPrivacyMutantTest' \
      --tests 'org.ghost.messaging.dmworld.DmEdgeStatisticsTest' \
      --tests 'org.ghost.messaging.dmworld.EdgeStatisticsSelfTest' \
      -Dghost.dm.native="$NATIVE" -Dghost.dm.privacy.report="$report" )
  local grc=$?
  echo "$grc" > "$MARKERS/suite.done"
  if [ "$grc" -ne 0 ]; then rc=1; return; fi
  bash "$GHOST/scripts/gates/dm-report-check.sh" "$report" privacy-suite || rc=1
}

case "$cmd" in
  worlds)
    for i in $(seq "$FROM" 9); do run_pair "$i"; done ;;
  suite)
    run_suite ;;
  all)
    for i in $(seq "$FROM" 9); do run_pair "$i"; done
    [ "$rc" = 0 ] && run_suite ;;
esac

if [ "$rc" = 0 ]; then echo "dm-privacy-gate: PASS ($cmd)"; else echo "dm-privacy-gate: FAIL ($cmd)" >&2; fi
exit "$rc"
