#!/usr/bin/env bash
# Gate (ADR-22, Phase 8 design §14.1, G-11): exact versions of the crypto crates, in Cargo.lock and
# per shipped graph, as listed in scripts/gates/rust-crypto-pins.txt (format in that file). A second
# rsa version reaching the client, a crypto-bigint bump under the issuer's signer or ring drifting
# between graphs fails here even though the name-based allowlists still pass.
# Self-test hooks (scripts/gates/self-test.sh): GHOST_CRYPTO_PINS reads another pins file;
# GHOST_CRYPTO_PINS_LOCK checks the `lock` lines against another (mutated) copy of Cargo.lock.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 2; }
PINS="${GHOST_CRYPTO_PINS:-$GATES_DIR/rust-crypto-pins.txt}"
LOCK="${GHOST_CRYPTO_PINS_LOCK:-$GHOST_ROOT/Cargo.lock}"
[ -f "$PINS" ] || { echo "pins file not found: $PINS" >&2; exit 2; }
[ -f "$LOCK" ] || { echo "lock file not found: $LOCK" >&2; exit 2; }
cd "$GHOST_ROOT"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# "name version" for every [[package]] of the lock file.
lock_pkgs="$(awk '/^\[\[package\]\]/ {n = ""} /^name = / {gsub(/"/, "", $3); n = $3} /^version = / {gsub(/"/, "", $3); if (n != "") print n " " $3}' "$LOCK")"
[ -n "$lock_pkgs" ] || { fail "no packages read from $LOCK"; finish rust-crypto-pins; }

graph_pkgs() { # $1 = package, $2 = targets; prints "name version" lines, cached per (package, targets)
  local cache t out
  cache="$work/$(printf '%s_%s' "$1" "$2" | tr -c 'A-Za-z0-9_\n-' '_')"
  if [ ! -f "$cache" ]; then
    : > "$cache.raw"
    for t in ${2//,/ }; do
      if ! out="$(cargo tree --locked -p "$1" -e normal,build --target "$t" --prefix none -f '{p}' 2>"$work/err" </dev/null)"; then
        cat "$work/err" >&2
        return 1
      fi
      printf '%s\n' "$out" >> "$cache.raw"
    done
    awk 'NF {sub(/^v/, "", $2); print $1 " " $2}' "$cache.raw" | sort -u > "$cache"
  fi
  cat "$cache"
}

versions_of() { # $1 = crate, stdin = "name version" lines; prints the versions space-separated
  awk -v n="$1" '$1 == n {print $2}' | sort -u | tr '\n' ' ' | sed 's/ $//'
}

lines=0
while read -r -a f; do
  [ "${#f[@]}" -gt 0 ] || continue
  case "${f[0]}" in
    '#'*) continue ;;
    lock)
      crate="${f[1]}"
      want="$(printf '%s\n' "${f[@]:2}" | sort -u | tr '\n' ' ' | sed 's/ $//')"
      got="$(printf '%s\n' "$lock_pkgs" | versions_of "$crate")"
      [ "$got" = "$want" ] || fail "Cargo.lock holds $crate [$got]; pinned [$want] ($PINS)"
      ;;
    graph)
      [ "${#f[@]}" -eq 6 ] || { fail "malformed pins line: ${f[*]}"; continue; }
      pkg="${f[1]}" targets="${f[2]}" crate="${f[3]}" version="${f[4]}" presence="${f[5]}"
      if ! pkgs="$(graph_pkgs "$pkg" "$targets")"; then
        fail "cargo tree failed for $pkg ($targets)"
        continue
      fi
      got="$(printf '%s\n' "$pkgs" | versions_of "$crate")"
      if [ -z "$got" ]; then
        [ "$presence" = required ] && fail "$pkg ($targets): $crate is missing (pinned $version, required)"
      elif [ "$got" != "$version" ]; then
        fail "$pkg ($targets): $crate resolves to [$got], pinned $version"
      fi
      ;;
    *) fail "unknown pins line: ${f[*]}" ;;
  esac
  lines=$((lines + 1))
done < <(grep -vE '^\s*(#|$)' "$PINS")
[ "$lines" -gt 0 ] || fail "no pins read from $PINS"
finish rust-crypto-pins
