#!/usr/bin/env bash
# The channel device probe (Phase 10 design §12.11, §19.29.3 R-21, §14 S2 exit; slice S2b): the
# successor of S0's `device_probe`, run **through the shipped library** — `libghost_client_net.so`
# as `scripts/build-native.sh` builds it, loaded by ART under `app_process` and called through its
# `MlsNative` JNI entry points (scripts/device/mls-probe/src/…/MlsProbe.java).
#
#   mls-probe.sh build <out-dir>
#       compiles the probe (javac, Java 11 bytecode) and dexes it (d8 of the newest build-tools)
#       into <out-dir>/mls-probe.dex. Needs JAVA_HOME (or javac on PATH) and ANDROID_HOME.
#   mls-probe.sh run <adb-serial> <mls-probe.dex> <libghost_client_net.so for the device's ABI> <argon2|round> <n>
#       pushes both to /data/local/tmp/mls-probe/ and runs the probe; prints `key value` lines and
#       exits non-zero when the probe does (a refused call, members that disagree, a load failure).
#
# The arm64-v8a run needs a phone (an arm64 device on adb): the dex is the same file, the library
# is build-native.sh's arm64-v8a one. Evidence tooling; nothing here ships.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cmd="${1:-}"
case "$cmd" in
  build)
    out="${2:?usage: mls-probe.sh build <out-dir>}"
    mkdir -p "$out/classes"
    javac_bin="javac"
    [ -n "${JAVA_HOME:-}" ] && javac_bin="$JAVA_HOME/bin/javac"
    java_bin="java"
    [ -n "${JAVA_HOME:-}" ] && java_bin="$JAVA_HOME/bin/java"
    sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
    [ -n "$sdk" ] || { echo "mls-probe: ANDROID_HOME is not set" >&2; exit 2; }
    tools="$(ls -d "$sdk"/build-tools/* | sort -V | tail -n 1)"
    srcs=()
    while IFS= read -r f; do srcs+=("$f"); done < <(find "$DIR/mls-probe/src" -name '*.java' | sort)
    "$javac_bin" --release 11 -d "$out/classes" "${srcs[@]}"
    classes=()
    while IFS= read -r f; do classes+=("$f"); done < <(find "$out/classes" -name '*.class' | sort)
    "$java_bin" -cp "$tools/lib/d8.jar" com.android.tools.r8.D8 --release --min-api 29 --output "$out" "${classes[@]}"
    mv "$out/classes.dex" "$out/mls-probe.dex"
    echo "mls-probe: $out/mls-probe.dex (d8 of $(basename "$tools"))"
    ;;
  run)
    serial="${2:?usage: mls-probe.sh run <serial> <dex> <library> <mode> <n>}"
    dex="${3:?dex}"
    lib="${4:?library}"
    mode="${5:-round}"
    n="${6:-5}"
    adb="${GHOST_ADB:-adb}"
    remote=/data/local/tmp/mls-probe
    "$adb" -s "$serial" shell mkdir -p "$remote"
    "$adb" -s "$serial" push "$dex" "$remote/mls-probe.dex" > /dev/null
    "$adb" -s "$serial" push "$lib" "$remote/libghost_client_net.so" > /dev/null
    echo "device $("$adb" -s "$serial" shell getprop ro.product.cpu.abi | tr -d '\r') sdk $("$adb" -s "$serial" shell getprop ro.build.version.sdk | tr -d '\r')"
    out="$("$adb" -s "$serial" shell "CLASSPATH=$remote/mls-probe.dex app_process $remote org.ghost.device.MlsProbe $mode $n $remote/libghost_client_net.so; echo exit=\$?" | tr -d '\r')"
    printf '%s\n' "$out"
    grep -qx 'exit=0' <<< "$out" && grep -q "^probe_ok $mode" <<< "$out"
    ;;
  *)
    echo "usage: mls-probe.sh build <out-dir> | run <serial> <dex> <library> <mode> <n>" >&2
    exit 2
    ;;
esac
