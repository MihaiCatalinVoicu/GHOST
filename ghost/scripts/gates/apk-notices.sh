#!/usr/bin/env bash
# Gate G-L3 (ADR-37; Phase 9 design §2.10.2): the APK carries assets/THIRD_PARTY_NOTICES.txt, and its
# bytes are the committed notices that license-notices.sh (G-L1) regenerates:
# licenses/apk-notices-preamble.txt, then licenses/THIRD_PARTY_NOTICES-android.txt, then
# licenses/THIRD_PARTY_NOTICES-client-net.txt (the order of app/build.gradle.kts).
# Usage: apk-notices.sh <apk>. CI: the android job after the build, and reproducible-build.sh.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
APK="${1:?usage: apk-notices.sh <apk>}"
[ -f "$APK" ] || { echo "no such APK: $APK" >&2; exit 2; }
command -v unzip >/dev/null || { echo "unzip not found" >&2; exit 2; }
LIC="$GHOST_ROOT/licenses"
work="$(mktemp -d)"
trap 'rc=$?; rm -rf "$work"; exit $rc' EXIT
for part in apk-notices-preamble.txt THIRD_PARTY_NOTICES-android.txt THIRD_PARTY_NOTICES-client-net.txt; do
  [ -s "$LIC/$part" ] || fail "licenses/$part is missing or empty"
done
[ "$FAILURES" -eq 0 ] || finish apk-notices
cat "$LIC/apk-notices-preamble.txt" "$LIC/THIRD_PARTY_NOTICES-android.txt" "$LIC/THIRD_PARTY_NOTICES-client-net.txt" > "$work/expected"
# A here-string, not `unzip -Z1 ... | grep -qx ...`: under `set -o pipefail`, grep's early exit on
# a match can SIGPIPE unzip while it is still listing entries, and the pipeline's exit status then
# reflects the SIGPIPE, not the match (self-test.sh and clippy-clearnet-fixture.sh hit the same
# class; see their comments).
listing="$(unzip -Z1 "$APK" 2>/dev/null || true)"
if ! grep -qx 'assets/THIRD_PARTY_NOTICES.txt' <<< "$listing"; then
  fail "$APK carries no assets/THIRD_PARTY_NOTICES.txt"
else
  unzip -p "$APK" assets/THIRD_PARTY_NOTICES.txt > "$work/actual"
  want="$(sha256sum "$work/expected" | cut -d' ' -f1)"
  got="$(sha256sum "$work/actual" | cut -d' ' -f1)"
  [ "$want" = "$got" ] || fail "$APK: assets/THIRD_PARTY_NOTICES.txt has SHA-256 $got; the committed notices give $want"
fi
finish apk-notices
