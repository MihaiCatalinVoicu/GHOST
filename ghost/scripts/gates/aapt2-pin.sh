#!/usr/bin/env bash
# aapt2-pin.sh — GATES-5 (review Faza 9 §22.34 item GATES-5): the aapt2 binary every Gradle build
# runs is outside Gradle's dependency verification (a trust regex covers it in
# verification-metadata.xml). This gate pins the installed build-tools' aapt2 binaries against
# scripts/gates/aapt2-pins.txt: a hash mismatch (tampering, a swapped binary, a silent SDK
# update) or an installed build-tools version with no pin entry fails the gate.
#
# Semantics: integrity pinning, trust-on-first-use (see the pins file header). Optional argument:
# the SDK root to check (defaults to $ANDROID_HOME); the override exists for the self-test's
# fixture SDK and for machines that keep the SDK elsewhere.
set -u
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
PINS="$GATES_DIR/aapt2-pins.txt"
SDK="${1:-${ANDROID_HOME:-}}"
case "$SDK" in
  --*) echo "usage: aapt2-pin.sh [sdk-root]" >&2; exit 2 ;;
esac
if [ -z "$SDK" ] || [ ! -d "$SDK/build-tools" ]; then
  # No SDK here (an auditor's bare checkout, a Rust-only runner): nothing to pin, nothing to fail.
  echo "[aapt2-pin] SKIPPED (no SDK)"
  exit 0
fi

fail=0
pinned() { # $1 = version, $2 = platform
  awk -v v="$1" -v p="$2" '$1 == v && $2 == p {print $3}' "$PINS"
}

shopt -s nullglob
for dir in "$SDK"/build-tools/*/; do
  v="$(basename "$dir")"
  case "$(uname -s)" in
    *NT*|MINGW*|CYGWIN*) bin="$dir/aapt2.exe"; platform="windows" ;;
    *) bin="$dir/aapt2"; platform="linux" ;;
  esac
  if [ ! -f "$bin" ]; then
    # A platform without the binary (e.g. Linux SDK checked from Windows tooling) is not checked.
    continue
  fi
  want="$(pinned "$v" "$platform")"
  if [ -z "$want" ]; then
    echo "aapt2-pin: build-tools $v ($platform) has no pin entry in aapt2-pins.txt (pin it deliberately or remove the version)" >&2
    fail=1
    continue
  fi
  got="$(sha256sum "$bin" | cut -d' ' -f1)"
  if [ "$got" != "$want" ]; then
    echo "aapt2-pin: aapt2 of build-tools $v ($platform) does not match the pin (got ${got:0:16}…, want ${want:0:16}…)" >&2
    fail=1
  fi
done
shopt -u nullglob

# Pin entries whose version is not installed are not an error (other machines pin other versions);
# they become live the moment that version appears.

if [ "$fail" = 1 ]; then
  echo "[aapt2-pin] FAILED" >&2
  exit 1
fi
echo "[aapt2-pin] OK"
exit 0
