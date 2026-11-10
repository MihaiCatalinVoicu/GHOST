#!/usr/bin/env bash
# ci-local.sh — the local equivalent of the legacy .github/workflows/ci.yml (ADR-58: CI is local).
# The eight jobs, their commands condensed from the workflow, with the Actions machinery (caches,
# artifacts, step summaries) replaced by the local convention: reports under
# ghost/t2-reports/ci-local/<job>/, every job's exit status accumulated, a failing job does not
# stop the others (fail-fast: false), and the summary at the end names every failing job.
#
# Where a job handed libraries to the next through the Actions cache, this script uses the
# filesystem: android-native writes android/network/src/main/jniLibs + native-libs.sha256, android
# and reproducible verify them the way the workflow's diff/sha256sum -c steps did.
#
# Usage: ci-local.sh [--only <job>] [--work <dir>]
#   jobs: static-gates rust android-native android sync-exit-gate reproducible live-tor pt-loopback
#         (live-tor and pt-loopback need network access to the live Tor directory; run them on
#          purpose, like the workflow's dispatch-only condition)
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST="$(cd "$DIR/../../" && pwd)"
ANDROID="$GHOST/android"
WORK="$GHOST/t2-reports/ci-local"
ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --only) ONLY="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    *) echo "ci-local: unknown argument: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$WORK"

JOBS=(static-gates rust android-native android sync-exit-gate reproducible live-tor pt-loopback)
if [ -n "$ONLY" ]; then
  case " ${JOBS[*]} " in
    *" $ONLY "*) JOBS=("$ONLY") ;;
    *) echo "ci-local: no such job: $ONLY" >&2; exit 2 ;;
  esac
fi

rc=0
fails=()
jobdir() { mkdir -p "$WORK/$1"; echo "$WORK/$1"; }

j_static_gates() { # static-gates (placeholder, logging, manifest, dependency allowlist, proto)
  local d; d="$(jobdir static-gates)"
  ( cd "$GHOST" && bash scripts/gates/run-all.sh ) > "$d/run-all.log" 2>&1 || return 1
  ( cd "$GHOST" && bash scripts/gates/self-test.sh ) > "$d/self-test.log" 2>&1 || return 1
}

j_rust() { # rust (fmt, clippy -D warnings, test, cargo-deny, cargo-audit, client allowlist, G-R3...)
  local d; d="$(jobdir rust)"
  ( cd "$GHOST" && \
    cargo fmt --all -- --check && \
    cargo clippy --locked --workspace --all-targets -- -D warnings && \
    cargo test --locked --workspace && \
    cargo deny check && \
    cargo audit ) > "$d/rust.log" 2>&1 || return 1
}

j_android_native() { # android-native (two same-path builds, identical hashes, G-R6/G-M6/G-R3/G-R7c)
  local d; d="$(jobdir android-native)"; local tmp="$d/native"
  rm -rf "$tmp"; mkdir -p "$tmp"
  ( cd "$GHOST" && \
    export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_SDK_ROOT/ndk/30.0.16248370}"; \
    bash scripts/build-native.sh "$tmp/native-a" "$tmp/a.sha256" && \
    rm -rf target/android-native && \
    bash scripts/build-native.sh "$tmp/native-b" "$tmp/b.sha256" && \
    diff "$tmp/a.sha256" "$tmp/b.sha256" && \
    mkdir -p android/network/src/main/jniLibs && \
    cp -r "$tmp/native-a/." android/network/src/main/jniLibs/ && \
    cp "$tmp/a.sha256" native-libs.sha256 && \
    bash scripts/gates/dm-jni-surface.sh \
      "$tmp/native-a/arm64-v8a/libghost_client_net.so" \
      "$tmp/native-a/x86_64/libghost_client_net.so" && \
    bash scripts/gates/mls-jni-surface.sh \
      "$tmp/native-a/arm64-v8a/libghost_client_net.so" \
      "$tmp/native-a/x86_64/libghost_client_net.so" && \
    bash scripts/gates/libcrux-portable.sh --with-aes \
      --target-dir target/android-native/aarch64-linux-android/release \
      --target-dir target/android-native/x86_64-linux-android/release && \
    bash scripts/gates/dm-golden-lock.sh --library \
      "$tmp/native-a/arm64-v8a/libghost_client_net.so" \
      "$tmp/native-a/x86_64/libghost_client_net.so" ) > "$d/android-native.log" 2>&1 || return 1
}

native_for_host() { # the ghost_dm_host library path for this host
  case "$(uname -s)" in
    *NT*|MINGW*|CYGWIN*) echo "$GHOST/target/release/ghost_dm_host.dll" ;;
    *)                   echo "$GHOST/target/release/libghost_dm_host.so" ;;
  esac
}

j_android() { # android (gradlew build with the provenance host, report checks, licence gates)
  local d; d="$(jobdir android)"
  local native; native="$(native_for_host)"
  ( cd "$GHOST" && \
    cargo clean -p libcrux-ml-kem -p libcrux-sha3 -p libcrux-intrinsics -p libcrux-aes --release 2>/dev/null || true; \
    cargo build -p ghost-dm-host --release --locked --features provenance \
      --message-format=json-render-diagnostics > "$d/dm-host-build.json" && \
    bash scripts/gates/libcrux-portable.sh --with-aes --json "$d/dm-host-build.json" ) \
    > "$d/host-build.log" 2>&1 || return 1
  ( cd "$ANDROID" && ./gradlew build --no-daemon -Dghost.dm.native="$native" ) \
    > "$d/gradle-build.log" 2>&1 || return 1
  ( cd "$ANDROID" && \
    for c in MlsResultCodesTest ChannelCodecTest ChannelVectorReplayTest MlsHandleLifecycleTest ChannelCryptoNativeTest; do \
      f="crypto-bridge/build/test-results/testDebugUnitTest/TEST-org.ghost.crypto.bridge.$c.xml"; \
      grep -q 'skipped="0"' "$f" || { echo "$c: no report, or a skipped test ($f)" >&2; exit 1; }; \
    done && \
    bash ../scripts/gates/dm-report-check.sh messaging/build/reports/dm/privacy.txt privacy-pr && \
    bash ../scripts/gates/dm-report-check.sh messaging/build/reports/dm/report.txt pr && \
    bash ../scripts/gates/dm-jni-surface.sh --test "$native" && \
    bash ../scripts/gates/mls-jni-surface.sh --test "$native" && \
    ./gradlew --no-daemon :app:releaseRuntimeComponents && \
    bash ../scripts/gates/license-notices.sh android app/build/licenses/release-runtime-components.txt && \
    bash ../scripts/gates/apk-notices.sh app/build/outputs/apk/release/app-release-unsigned.apk && \
    bash ../scripts/gates/merged-manifest-lint.sh && \
    bash ../scripts/gates/apk-no-debug-hooks.sh app/build/outputs/mapping/release/mapping.txt ) \
    > "$d/checks.log" 2>&1 || return 1
  ( cd "$GHOST" && \
    bash scripts/gates/pt-size.sh && \
    bash scripts/gates/apk-pt-assets.sh android/app/build/outputs/apk/release/app-release-unsigned.apk ) \
    > "$d/pt-gates.log" 2>&1 || return 1
}

j_sync_exit_gate() {
  local d; d="$(jobdir sync-exit-gate)"
  local report="$ANDROID/sync/build/harness/report.txt"
  ( cd "$ANDROID" && ./gradlew --no-daemon :sync:testDebugUnitTest --rerun \
      -Dghost.sync.seeds=20000 -Dghost.sync.exhaustive=full ) > "$d/sync.log" 2>&1 || return 1
  fail=0
  for line in '^seeded worlds: 20000 seeds, ' '^mutants: 19 run' '^crashes injected=[0-9]+ caught at the top level=[0-9]+$'; do
    if ! grep -Eq "$line" "$report" 2>/dev/null; then
      echo "sync harness report: no line matching $line" >&2; fail=1
    fi
  done
  cp "$report" "$d/report.txt" 2>/dev/null || true
  return "$fail"
}

j_reproducible() {
  local d; d="$(jobdir reproducible)"
  ( cd "$GHOST" && \
    bash scripts/gates/reproducible-build.sh "$d/repro" native-libs.sha256 ) \
    > "$d/reproducible.log" 2>&1 || return 1
}

j_live_tor() {
  local d; d="$(jobdir live-tor)"
  ( cd "$GHOST" && GHOST_LIVE_LOG=info TMPDIR="$d" \
      cargo test -p ghost-client-net --locked --test live_tor -- --ignored --nocapture ) \
    > "$d/live-tor.log" 2>&1 || return 1
}

j_pt_loopback() {
  local d; d="$(jobdir pt-loopback)"
  ( cd "$GHOST" && \
    bash scripts/gates/pt-double-build.sh && \
    bash third_party/tor-expert/FETCH.sh && \
    GHOST_LIVE_LOG=info TMPDIR="$d" \
      cargo test --locked -p ghost-client-net --test pt_loopback -- --ignored --nocapture --test-threads=1 ) \
    > "$d/pt-loopback.log" 2>&1 || return 1
}

for job in "${JOBS[@]}"; do
  echo "ci-local: job $job"
  case "$job" in
    static-gates)    j_static_gates ;;
    rust)            j_rust ;;
    android-native)  j_android_native ;;
    android)         j_android ;;
    sync-exit-gate)  j_sync_exit_gate ;;
    reproducible)    j_reproducible ;;
    live-tor)        j_live_tor ;;
    pt-loopback)     j_pt_loopback ;;
  esac
  if [ $? -eq 0 ]; then
    echo "ci-local: job $job PASS"
  else
    echo "ci-local: job $job FAIL (log: $WORK/$job/)" >&2
    rc=1; fails+=("$job")
  fi
done

if [ "$rc" = 0 ]; then
  echo "ci-local: PASS (${#JOBS[@]} jobs)"
else
  echo "ci-local: FAIL — jobs: ${fails[*]}" >&2
fi
exit "$rc"
