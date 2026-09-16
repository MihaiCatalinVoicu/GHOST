#!/usr/bin/env bash
# V-14: replays vectors/ed25519-v14.txt on the JDK with BouncyCastle bcprov-jdk18on 1.85.2 (the
# :identity pin, libs.versions.toml). Usage: v14-ed25519-jvm.sh [bcprov jar]
set -euo pipefail
SPIKE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JAR="${1:-$(find "$HOME/.gradle/caches/modules-2/files-2.1/org.bouncycastle/bcprov-jdk18on/1.85.2" -name 'bcprov-jdk18on-1.85.2.jar' | head -1)}"
[ -f "$JAR" ] || { echo "bcprov-jdk18on-1.85.2.jar not found" >&2; exit 2; }
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
SEP=":"
native() { printf '%s' "$1"; }
if command -v cygpath >/dev/null 2>&1; then SEP=";"; native() { cygpath -w "$1"; }; fi
javac --release 17 -cp "$(native "$JAR")" -d "$(native "$OUT")" "$(native "$SPIKE/jvm/Ed25519Equivalence.java")"
java -cp "$(native "$OUT")$SEP$(native "$JAR")" Ed25519Equivalence "$(native "$SPIKE/vectors/ed25519-v14.txt")"
