#!/usr/bin/env bash
# Gate T7 for Rust (ADR-06, ADR-19): every package linked into the Android client library, on
# every shipped ABI, must be on client-core/rust-dependency-allowlist.txt. Mirrors the Gradle
# allowlist so a new HTTP client, telemetry or crash SDK cannot enter the APK through the Rust
# side unreviewed. Matching is by package name.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 2; }
ALLOW="${GHOST_RUST_ALLOWLIST:-$GHOST_ROOT/client-core/rust-dependency-allowlist.txt}"
TARGETS="aarch64-linux-android x86_64-linux-android" # keep in sync with scripts/build-native.sh
cd "$GHOST_ROOT"
err="$(mktemp)"
trap 'rm -f "$err"' EXIT
actual=""
for t in $TARGETS; do
  if ! out="$(cargo tree -p ghost-client-net -e normal --target "$t" --prefix none --locked -f '{p}' 2>"$err")"; then
    cat "$err" >&2
    fail "cargo tree failed for $t (is Cargo.lock in sync?)"
    finish rust-client-allowlist
  fi
  actual+="$out"$'\n'
done
actual="$(printf '%s' "$actual" | awk 'NF {print $1}' | sort -u)"
[ -n "$actual" ] || { fail "cargo tree produced no output"; finish rust-client-allowlist; }
allowed="$(grep -vE '^\s*(#|$)' "$ALLOW" | sort -u)"
while IFS= read -r pkg; do
  [ -n "$pkg" ] && fail "Rust package '$pkg' is linked into the client but not allowlisted ($ALLOW)"
done < <(comm -23 <(echo "$actual") <(echo "$allowed"))
finish rust-client-allowlist
