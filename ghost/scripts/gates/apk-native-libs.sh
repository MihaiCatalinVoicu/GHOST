#!/usr/bin/env bash
# Gate T12, native part (ADR-07, ADR-19): the APK must carry libghost_client_net.so for every
# shipped ABI with exactly the bytes listed in <sums-file> (written by scripts/build-native.sh),
# no ABI directory other than arm64-v8a/x86_64, and no native library outside NATIVE_ALLOWLIST
# (a new AAR bringing its own .so, e.g. a telemetry SDK, fails here as well as in Gradle T7).
# This proves the APK packages the libraries produced by that build run; it is not an
# independent review of those bytes, and third-party .so files are checked by name only.
# Usage: apk-native-libs.sh <apk> <sums-file>
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
APK="${1:?usage: apk-native-libs.sh <apk> <sums-file>}"
SUMS="${2:?usage: apk-native-libs.sh <apk> <sums-file>}"
ABIS=(arm64-v8a x86_64)
# Native libraries allowed in the APK, per ABI. Adding one needs review (ADR-06).
NATIVE_ALLOWLIST=(
  libghost_client_net.so        # GHOST Tor/network core (ADR-19), checked by hash
  libsqlcipher.so               # net.zetetic:sqlcipher-android (ADR-05, storage)
  libandroidx.graphics.path.so  # androidx.graphics:graphics-path (via androidx.compose.ui:ui-graphics)
)
[ -f "$APK" ] || { fail "missing $APK"; finish apk-native-libs; }
[ -s "$SUMS" ] || { fail "missing or empty $SUMS"; finish apk-native-libs; }
listing="$(unzip -Z1 "$APK" | grep '^lib/' || true)"
for abi in "${ABIS[@]}"; do
  entry="lib/$abi/libghost_client_net.so"
  if ! printf '%s\n' "$listing" | grep -qx "$entry"; then
    fail "APK lacks $entry"
    continue
  fi
  got="$(unzip -p "$APK" "$entry" | sha256sum | cut -d' ' -f1)"
  want="$(awk -v f="$abi/libghost_client_net.so" '$2 == f || $2 == "*"f {print $1}' "$SUMS")"
  [ -n "$want" ] || { fail "$abi not listed in $SUMS"; continue; }
  [ "$got" = "$want" ] || fail "$entry in APK ($got) differs from the recorded build ($want)"
done
for dir in $(printf '%s\n' "$listing" | awk -F/ 'NF>=3 {print $2}' | sort -u); do
  printf '%s\n' "${ABIS[@]}" | grep -qx "$dir" || fail "APK ships unexpected ABI directory lib/$dir"
done
while IFS= read -r entry; do
  [ -n "$entry" ] || continue
  name="${entry##*/}"
  [ -n "$name" ] || continue
  printf '%s\n' "${NATIVE_ALLOWLIST[@]}" | grep -qx "$name" \
    || fail "APK ships native library $entry, which is not on the native allowlist"
done <<< "$listing"
finish apk-native-libs
