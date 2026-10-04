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
# G-M7 (Phase 11 design faza11-media.md §13.1, §16.1 G-M7; slice S1): the media crate
# `ghost-client-media` is checked the same way before slice S2 links it into `ghost-client-dm` (and so
# into `ghost-client-net`), as ghost-client-mls was before S2b: its graph on both triples is on the
# allowlist (one workspace line, no external crate: its graph is the DM crate's AEAD, HKDF, SHA-2 and
# zeroize stack) and in the duplicate union; and its **direct** normal dependencies are design
# §13.1's chacha20poly1305, hkdf, hmac, sha2 and zeroize at most, so a crate the allowlist already
# holds for another reason (tokio, say) cannot become the media crate's dependency unreviewed.
# Self-test hooks (scripts/gates/self-test.sh): GHOST_RUST_ALLOWLIST reads another allowlist;
# GHOST_ALLOWLIST_MLS_PACKAGE and GHOST_ALLOWLIST_NET_PACKAGE name other packages as the two roots;
# GHOST_RUST_DUPLICATES reads another duplicate baseline; GHOST_ALLOWLIST_WORKSPACE runs the queries
# in another workspace (the linked-state fixture: a root that links the three crates);
# GHOST_ALLOWLIST_MEDIA_PACKAGE names another package as the media root and GHOST_ALLOWLIST_MEDIA_DEPS
# replaces its allowed direct dependencies.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 2; }
ALLOW="${GHOST_RUST_ALLOWLIST:-$GHOST_ROOT/client-core/rust-dependency-allowlist.txt}"
DUPS="${GHOST_RUST_DUPLICATES:-$GHOST_ROOT/client-core/rust-duplicate-versions.txt}"
MLS="${GHOST_ALLOWLIST_MLS_PACKAGE:-ghost-client-mls}"
NET="${GHOST_ALLOWLIST_NET_PACKAGE:-ghost-client-net}"
MEDIA="${GHOST_ALLOWLIST_MEDIA_PACKAGE:-ghost-client-media}"
MEDIA_DEPS="${GHOST_ALLOWLIST_MEDIA_DEPS:-chacha20poly1305 hkdf hmac sha2 zeroize}"
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
  media="$(graph "$MEDIA" "$t")"
  grep -q "^$MEDIA " <<< "$media" || fail "$MEDIA is not in its own graph on $t (the media clause would pass vacuously)"
  actual+="$net"$'\n'"$mls"$'\n'"$media"$'\n'
  # G-M1: no name at more versions in the union than the baseline allows.
  union="$(printf '%s\n%s\n%s\n' "$net" "$mls" "$media" | awk 'NF' | sort -u)"
  dups="$(awk '{c[$1]++; v[$1] = v[$1] " " $2} END {for (n in c) if (c[n] > 1) print n " " c[n] v[n]}' <<< "$union" | sort)"
  while read -r name count versions; do
    [ -n "$name" ] || continue
    reached+="$name $count"$'\n'
    allowed="$(awk -v n="$name" '$1 == n {print $2}' <<< "$baseline")"
    if [ -z "$allowed" ] || [ "$count" -gt "$allowed" ]; then
      fail "$name is at $count versions ($versions) in the union of $NET's, $MLS's and $MEDIA's graphs on $t; $(basename "$DUPS") allows ${allowed:-1} (G-M1: no second copy of a crate in the library unreviewed)"
    fi
  done <<< "$dups"
done
while read -r name count; do
  [ -n "$name" ] || continue
  most="$(awk -v n="$name" '$1 == n && $2 > m {m = $2} END {print m + 0}' <<< "$reached")"
  [ "$most" -ge "$count" ] || fail "$(basename "$DUPS"): $name $count is stale (the graphs hold it at ${most} version(s) at most; lower or remove the line)"
done <<< "$baseline"
# G-M7: the media crate's direct normal dependencies (any target) are design §13.1's five at most.
if ! direct_raw="$(cargo tree -p "$MEDIA" -e normal --target all --depth 1 --prefix none --locked -f '{p}' 2>"$err")"; then
  cat "$err" >&2
  fail "cargo tree failed for $MEDIA's direct dependencies"
  direct_raw=""
fi
direct="$(awk 'NR > 1 && NF {print $1}' <<< "$direct_raw" | sort -u)"
[ -n "$direct" ] || fail "$MEDIA has no direct dependency in the query (the G-M7 clause would pass vacuously)"
while IFS= read -r d; do
  [ -n "$d" ] || continue
  case " $MEDIA_DEPS " in
    *" $d "*) ;;
    *) fail "$MEDIA depends on '$d' directly: design §13.1 allows $MEDIA_DEPS (G-M7: no other external crate)" ;;
  esac
done <<< "$direct"
actual="$(printf '%s' "$actual" | awk 'NF {print $1}' | sort -u)"
[ -n "$actual" ] || { fail "cargo tree produced no output"; finish rust-client-allowlist; }
allowed="$(grep -vE '^\s*(#|$)' "$ALLOW" | sort -u)"
while IFS= read -r pkg; do
  [ -n "$pkg" ] && fail "Rust package '$pkg' is linked into the client but not allowlisted ($ALLOW)"
done < <(comm -23 <(echo "$actual") <(echo "$allowed"))
finish rust-client-allowlist
