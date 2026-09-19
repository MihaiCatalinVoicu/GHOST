#!/usr/bin/env bash
# V-5: builds the spike as a host cdylib with JNI exports (the ghost-dm-host shape of design §2.3),
# lists its Java_ exports, and loads it into a JDK 17 JVM (jvm/org/ghost/dmspike/DmHostProbe.java).
# Works on Windows (MSVC, Git Bash) and Linux. Needs cargo, javac/java 17 and llvm-objdump (the
# NDK's when ANDROID_NDK_HOME is set, else llvm-objdump or objdump on PATH).
set -euo pipefail
SPIKE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SPIKE"
cargo build --release --features jni-host --lib
TARGET="${CARGO_TARGET_DIR:-$SPIKE/target}/release"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) LIB="$TARGET/ghost_dm_spike.dll" ;;
  Darwin) LIB="$TARGET/libghost_dm_spike.dylib" ;;
  *) LIB="$TARGET/libghost_dm_spike.so" ;;
esac
[ -f "$LIB" ] || { echo "missing $LIB" >&2; exit 1; }

OBJDUMP="${OBJDUMP:-}"
if [ -z "$OBJDUMP" ] && [ -n "${ANDROID_NDK_HOME:-}" ]; then
  for candidate in "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-objdump*; do
    [ -f "$candidate" ] && OBJDUMP="$candidate" && break
  done
fi
[ -n "$OBJDUMP" ] || OBJDUMP="$(command -v llvm-objdump || command -v objdump)"
echo "library: $LIB ($(wc -c < "$LIB") bytes)"
# PE: the export table (-p); ELF: the dynamic symbol table (-T).
exports="$({ "$OBJDUMP" -p "$LIB" 2>/dev/null || true; "$OBJDUMP" -T "$LIB" 2>/dev/null || true; } | grep -o 'Java_org_ghost_dmspike_[A-Za-z_]*' | sort -u || true)"
echo "exports:"
printf '%s\n' "$exports"
[ "$(printf '%s\n' "$exports" | grep -c Java_ || true)" = "3" ] || { echo "expected 3 JNI exports" >&2; exit 1; }

native() { printf '%s' "$1"; }
if command -v cygpath >/dev/null 2>&1; then native() { cygpath -w "$1"; }; fi
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
javac --release 17 -d "$(native "$OUT")" "$(native "$SPIKE/jvm/org/ghost/dmspike/DmHostProbe.java")"
java -cp "$(native "$OUT")" org.ghost.dmspike.DmHostProbe "$(native "$LIB")"
