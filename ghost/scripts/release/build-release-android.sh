#!/usr/bin/env bash
# build-release-android.sh <tag> [--out <dir>] — the Android half of recipe A, as a THIN
# wrapper over the unified recipe (docs/design/faza14-distribution.md §6, slice S3d): the
# unified build-release.sh owns the recipe; this entry point exists so the android selfcheck
# (infra/builder/selfcheck-android.sh) keeps its invocation and its ANDROID_SELFCHECK_EQUAL
# shape — two runs of the --android-only mode, byte-equal apk/, lib/ and symbols/.
#
# The unified script carries the tag re-exec guard itself (it re-execs from the tag's archive
# whenever the caller's copy differs), so a stale wrapper cannot define the recipe either.
set -euo pipefail

TAG="${1:?usage: build-release-android.sh <tag> [--out <dir>]}"
OUT="${2:-$(pwd)/build-out-android}"
[ "${2:-}" = "--out" ] && OUT="${3:?--out needs a directory}"

GHOST="$(cd "$(dirname "$0")" && pwd)"
exec bash "$GHOST/build-release.sh" "$TAG" --out "$OUT" --android-only
