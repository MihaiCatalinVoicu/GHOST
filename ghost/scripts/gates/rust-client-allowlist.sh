#!/usr/bin/env bash
# Gate T7 for Rust (ADR-06, ADR-19): every package linked into the Android client library, on
# every shipped ABI, must be on client-core/rust-dependency-allowlist.txt. Mirrors the Gradle
# allowlist so a new HTTP client, telemetry or crash SDK cannot enter the APK through the Rust
# side unreviewed. Matching is by package name.
#
# G-M1 (Phase 10 design faza10-forum.md §13.1; slice S2a, corrected by the review of S2a, F2,
# §19.31): the channel crate `ghost-client-mls` is checked the same way before slice S2b links it
# into `ghost-client-net` (its JNI export), and **no name may reach more versions in the union of
# the two graphs than client-core/rust-duplicate-versions.txt allows** (V10-1: the OpenMLS stack adds
# 22 names and no second version of any; a bump that did would put two copies of a crate into the
# library and escape the name-based list). The union is the right set before and after S2b: S2a's
# rule compared the MLS graph with the client graph's versions, which stops meaning anything once
# the client graph contains the MLS graph (every version it brings is then "already present"); a
# committed count per name does not. A baseline line whose name no longer reaches its count fails
# too, so the file stays the graph's exact list.
# Self-test hooks (scripts/gates/self-test.sh): GHOST_RUST_ALLOWLIST reads another allowlist;
# GHOST_ALLOWLIST_MLS_PACKAGE and GHOST_ALLOWLIST_NET_PACKAGE name other packages as the two roots;
# GHOST_RUST_DUPLICATES reads another duplicate baseline; GHOST_ALLOWLIST_WORKSPACE runs the queries
# in another workspace (the linked-state fixture: a root that links both crates).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 2; }
ALLOW="${GHOST_RUST_ALLOWLIST:-$GHOST_ROOT/client-core/rust-dependency-allowlist.txt}"
DUPS="${GHOST_RUST_DUPLICATES:-$GHOST_ROOT/client-core/rust-duplicate-versions.txt}"
MLS="${GHOST_ALLOWLIST_MLS_PACKAGE:-ghost-client-mls}"
NET="${GHOST_ALLOWLIST_NET_PACKAGE:-ghost-client-net}"
TARGETS="aarch64-linux-android x86_64-linux-android" # keep in sync with scripts/build-native.sh
cd "${GHOST_ALLOWLIST_WORKSPACE:-$GHOST_ROOT}"
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
[ -f "$DUPS" ] || { fail "$DUPS is missing (G-M1's duplicate baseline)"; finish rust-client-allowlist; }
baseline="$(grep -vE '^\s*(#|$)' "$DUPS" | awk '{print $1 " " $2}')"
while read -r name count; do
  [ -n "$name" ] || continue
  [[ "$count" =~ ^[2-9]$ ]] || fail "$(basename "$DUPS"): '$name $count' is not a name with a version count of 2 or more"
done <<< "$baseline"
actual=""
reached="" # "name count" of every duplicated name, over the triples
for t in $TARGETS; do
  net="$(graph "$NET" "$t")"
  mls="$(graph "$MLS" "$t")"
  grep -q "^$MLS " <<< "$mls" || fail "$MLS is not in its own graph on $t (the MLS clause would pass vacuously)"
  actual+="$net"$'\n'"$mls"$'\n'
  # G-M1: no name at more versions in the union than the baseline allows.
  union="$(printf '%s\n%s\n' "$net" "$mls" | awk 'NF' | sort -u)"
  dups="$(awk '{c[$1]++; v[$1] = v[$1] " " $2} END {for (n in c) if (c[n] > 1) print n " " c[n] v[n]}' <<< "$union" | sort)"
  while read -r name count versions; do
    [ -n "$name" ] || continue
    reached+="$name $count"$'\n'
    allowed="$(awk -v n="$name" '$1 == n {print $2}' <<< "$baseline")"
    if [ -z "$allowed" ] || [ "$count" -gt "$allowed" ]; then
      fail "$name is at $count versions ($versions) in the union of $NET's and $MLS's graphs on $t; $(basename "$DUPS") allows ${allowed:-1} (G-M1: no second copy of a crate in the library unreviewed)"
    fi
  done <<< "$dups"
done
while read -r name count; do
  [ -n "$name" ] || continue
  most="$(awk -v n="$name" '$1 == n && $2 > m {m = $2} END {print m + 0}' <<< "$reached")"
  [ "$most" -ge "$count" ] || fail "$(basename "$DUPS"): $name $count is stale (the graphs hold it at ${most} version(s) at most; lower or remove the line)"
done <<< "$baseline"
actual="$(printf '%s' "$actual" | awk 'NF {print $1}' | sort -u)"
[ -n "$actual" ] || { fail "cargo tree produced no output"; finish rust-client-allowlist; }
allowed="$(grep -vE '^\s*(#|$)' "$ALLOW" | sort -u)"
while IFS= read -r pkg; do
  [ -n "$pkg" ] && fail "Rust package '$pkg' is linked into the client but not allowlisted ($ALLOW)"
done < <(comm -23 <(echo "$actual") <(echo "$allowed"))
finish rust-client-allowlist
