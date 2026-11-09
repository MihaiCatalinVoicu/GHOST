#!/usr/bin/env bash
# Gate G-M8 (Phase 11 design faza11-media.md §16.1 G-M8; slice S9): **a Media3 bump cannot land
# without its goldens.** Media3 internals change between versions (muxer writes, extractor seek
# logic — design R-M2), so the walker's canonical profile is pinned to recorded encoder output,
# never to the library's sources:
#
#   always        the catalog holds exactly one Media3 version (a bump replaces the pin, it never
#                 adds one), and `protocol/test-vectors/media-goldens/media3-<version>/` exists with
#                 a non-empty, well-formed SHA256SUMS whose every listed file exists and hashes as
#                 committed (sha256sum -c), so the recorded goldens are intact and no golden is
#                 added without its sum;
#   at a bump     the new version's golden directory exists (the always-rule, re-stated against the
#                 base's pin) and the walker passes every file in it: the media crate's golden
#                 tests (`cargo test -p ghost-client-media --test goldens` — every committed fMP4
#                 and JPEG golden walks, the sums are the committed ones, and each golden seals and
#                 reads back to itself) run and pass with 0 ignored.
#
# The base is `--base <rev>` (CI passes the pull request's base or the push's previous head), else
# `$GHOST_MEDIA_GOLDEN_BASE`, else `HEAD~1`; it needs the git history and fails closed without it.
# `--base none` declares that there is no base (the first pin).
#
# Runs in the CI `rust` job (the bump drill) and in `run-all.sh` (the always-rule; the drill is
# CI's, as for G-R7). Self-test hooks, mirroring dm-golden-lock.sh: GHOST_MEDIA_GOLDEN_CATALOG=<file>
# reads the current catalog from a file; GHOST_MEDIA_GOLDEN_BASE_CATALOG=<file> reads the base's
# catalog from a file instead of git; GHOST_MEDIA_GOLDEN_DIR=<dir> replaces
# `protocol/test-vectors/media-goldens`; GHOST_MEDIA_GOLDEN_NO_TESTS=1 skips the cargo drill (the
# fixtures' machines have no cargo).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
export CARGO_TERM_COLOR=never
cd "$GHOST_ROOT"

usage() { echo "usage: media-golden-lock.sh [--base <rev>|none]" >&2; exit 2; }
base="${GHOST_MEDIA_GOLDEN_BASE:-HEAD~1}"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --base) [ -n "${2:-}" ] || usage; base="$2"; shift 2 ;;
    *) usage ;;
  esac
done

CATALOG="${GHOST_MEDIA_GOLDEN_CATALOG:-android/gradle/libs.versions.toml}"
GOLDENS="${GHOST_MEDIA_GOLDEN_DIR:-protocol/test-vectors/media-goldens}"

# The Media3 version the catalog pins: `media3 = "x.y.z"` lines (the version catalog's own key,
# not an artifact alias).
catalog_pin() { # $1 = catalog text
  { grep -oE '^media3 = "[0-9]+\.[0-9]+\.[0-9]+"' <<< "$1" || true; } | sed -E 's/^media3 = "([^"]+)"/\1/' | sort -u
}

[ -f "$CATALOG" ] || { echo "media-golden-lock: no catalog at $CATALOG" >&2; exit 2; }
current_catalog="$(cat "$CATALOG")"
now="$(catalog_pin "$current_catalog")"
case "$(grep -c . <<< "$now")" in
  1) ;;
  0) fail "the catalog holds no media3 version (G-M8 would pass vacuously)"; finish media-golden-lock ;;
  *) fail "the catalog holds several media3 versions ($(tr '\n' ' ' <<< "$now")): a bump replaces the pin, it never adds one"; finish media-golden-lock ;;
esac
now="$(head -1 <<< "$now")"

dir="$GOLDENS/media3-$now"
sums="$dir/SHA256SUMS"
[ -d "$dir" ] || fail "media3 $now: the golden directory $dir is missing (every pin commits its goldens, design §16.1 G-M8)"
if [ -d "$dir" ]; then
  [ -f "$sums" ] || fail "media3 $now: $sums is missing (the sums pin the committed goldens)"
fi
if [ -f "$sums" ]; then
  entries="$(grep -cE '^[0-9a-f]{64} \*' "$sums" || true)"
  [ "$entries" -gt 0 ] || fail "$sums lists no goldens (an empty sum file would pass vacuously)"
  # Every listed file exists and hashes as committed; a golden added without its sum is invisible
  # to -c, so the strict check is the listed-files one (the crate's `the_sums_are_the_committed_ones`
  # pins the reverse direction, and runs in the drill below at a bump).
  ( cd "$dir" && sha256sum -c SHA256SUMS >/dev/null ) || fail "$sums: a golden is missing or does not hash as committed"
fi

changed=0
if [ -n "${GHOST_MEDIA_GOLDEN_BASE_CATALOG:-}" ]; then
  base_catalog="$(cat "$GHOST_MEDIA_GOLDEN_BASE_CATALOG")"
elif [ "$base" = none ]; then
  base_catalog=""
else
  command -v git >/dev/null || { echo "git not found" >&2; exit 2; }
  if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = true ]; then
    fail "the repository is shallow: G-M8 needs the base's catalog (CI: fetch-depth 0), or --base none for the first pin"
    finish media-golden-lock
  fi
  if ! base_catalog="$(git show "$base:./$CATALOG" 2>/dev/null)"; then
    fail "cannot read $CATALOG at the base '$base' (G-M8 fails closed; pass --base <rev> or --base none)"
    finish media-golden-lock
  fi
fi
was="$(catalog_pin "$base_catalog")"
if [ -n "$was" ] && [ "$was" != "$now" ]; then changed=1; fi
echo "[media-golden-lock] media3 ${was:-none} -> $now$( [ "$changed" = 1 ] && echo ' (bump)' ) (base: $base)"

if [ "$changed" = 1 ]; then
  if [ "${GHOST_MEDIA_GOLDEN_NO_TESTS:-}" != 1 ]; then
    command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 2; }
    work="$(mktemp -d)"
    trap 'rc=$?; rm -rf "$work"; exit $rc' EXIT
    cargo test --locked -p ghost-client-media --test goldens 2>&1 | tr -d '\r' > "$work/run" || true
    grep -qE '^test result: ok\. [1-9][0-9]* passed; 0 failed;  0 ignored;' "$work/run" || \
      fail "the golden drill did not pass with 0 ignored: $(grep -E '^test result:' "$work/run" | sed -n '1p')"
    for t in the_sums_are_the_committed_ones every_fmp4_golden_is_canonical \
             every_jpeg_golden_is_canonical_and_a_fixed_point every_golden_seals_and_reads_back_to_itself; do
      grep -qxF "test $t ... ok" "$work/run" || fail "at the bump, the walker's $t did not run and pass"
    done
    echo "[media-golden-lock] bump drill: $(grep -c ' \.\.\. ok$' "$work/run") golden tests passed over media3-$now"
  fi
else
  [ -n "$was" ] || echo "[media-golden-lock] no media3 at the base: first pin, exempt from the bump drill"
fi
finish media-golden-lock
