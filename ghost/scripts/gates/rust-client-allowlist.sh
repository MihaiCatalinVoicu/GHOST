#!/usr/bin/env bash
# Gate T7 for Rust (ADR-06, ADR-19): every package linked into the Android client library, on
# every shipped ABI, must be on client-core/rust-dependency-allowlist.txt. Mirrors the Gradle
# allowlist so a new HTTP client, telemetry or crash SDK cannot enter the APK through the Rust
# side unreviewed. Matching is by package name.
#
# G-M1 (Phase 10 design faza10-forum.md §13.1; slice S2a): the channel crate `ghost-client-mls` is
# checked the same way before slice S2b links it into `ghost-client-net` (its JNI export), and its
# graph may add names but **no new version of a name the client graph already has** (V10-1: the
# OpenMLS stack adds 22 names and no second version of any; a bump that did would put two copies of
# a crate into the library and escape the name-based list). Once S2b links the crate, the second
# rule compares the MLS graph with a graph that contains it, and still holds.
# Self-test hooks (scripts/gates/self-test.sh): GHOST_RUST_ALLOWLIST reads another allowlist;
# GHOST_ALLOWLIST_MLS_PACKAGE names another package as the MLS graph's root.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 2; }
ALLOW="${GHOST_RUST_ALLOWLIST:-$GHOST_ROOT/client-core/rust-dependency-allowlist.txt}"
MLS="${GHOST_ALLOWLIST_MLS_PACKAGE:-ghost-client-mls}"
TARGETS="aarch64-linux-android x86_64-linux-android" # keep in sync with scripts/build-native.sh
cd "$GHOST_ROOT"
err="$(mktemp)"
trap 'rm -f "$err"' EXIT
graph() { # $1 = package, $2 = target: "name version" lines of its normal graph
  local out
  if ! out="$(cargo tree -p "$1" -e normal --target "$2" --prefix none --locked -f '{p}' 2>"$err")"; then
    cat "$err" >&2
    fail "cargo tree failed for $1 on $2 (is Cargo.lock in sync?)"
    finish rust-client-allowlist
  fi
  printf '%s\n' "$out" | sed 's/ (\*)//; s/ (proc-macro)//' | awk 'NF {sub(/^v/, "", $2); print $1 " " $2}' | sort -u
}
actual=""
for t in $TARGETS; do
  net="$(graph ghost-client-net "$t")"
  mls="$(graph "$MLS" "$t")"
  grep -q "^$MLS " <<< "$mls" || fail "$MLS is not in its own graph on $t (the MLS clause would pass vacuously)"
  actual+="$net"$'\n'"$mls"$'\n'
  # G-M1: no new version of a name the client graph already has.
  while read -r name version; do
    [ -n "$name" ] || continue
    have="$(awk -v n="$name" '$1 == n {print $2}' <<< "$net")"
    [ -z "$have" ] && continue
    grep -qx -- "$version" <<< "$have" \
      || fail "$MLS brings $name $version on $t; the client graph has $name $(tr '\n' ' ' <<< "$have")(G-M1: no new version of a name already present)"
  done <<< "$mls"
done
actual="$(printf '%s' "$actual" | awk 'NF {print $1}' | sort -u)"
[ -n "$actual" ] || { fail "cargo tree produced no output"; finish rust-client-allowlist; }
allowed="$(grep -vE '^\s*(#|$)' "$ALLOW" | sort -u)"
while IFS= read -r pkg; do
  [ -n "$pkg" ] && fail "Rust package '$pkg' is linked into the client but not allowlisted ($ALLOW)"
done < <(comm -23 <(echo "$actual") <(echo "$allowed"))
finish rust-client-allowlist
