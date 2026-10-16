#!/usr/bin/env bash
# Gate G-M10 (Phase 11 design faza11-media.md §16.1 G-M10, S0-10/V-M14; slice S7): the
# release-dex absence check. R8 removes a measured set of Media3 classes from a correctly
# configured app (GHOST's renderers factory, GHOST's data source, no caches, downloads or
# platform bitmap decoders); a release that KEEPS one means GHOST code started referencing
# it. The gate reads R8's mapping.txt and usage.txt of the :app release build and fails when
# any class of the removable set is kept.
#   Removable set (S0 V-M14, measured on 1.11.1): SimpleCache, CacheDataSource, CacheDataSink,
#   CacheWriter, DownloadManager, DownloadService, DownloadHelper, HttpEngineDataSource,
#   AesCipherDataSource, AesCipherDataSink, DataSourceInputStream,
#   InAppFragmentedMp4Muxer, EventLogger, every media3.database class (StandaloneDatabaseProvider
#   and friends), DefaultRenderersFactory, ImageRenderer, BitmapFactoryImageDecoder,
#   TextRenderer, MetadataRenderer.
#   "Kept": the class appears in mapping.txt with an obfuscation arrow. A class present only
#   in usage.txt's removed report is gone, which is the required shape; the usage.txt read is
#   the guard against a mapping that stopped reporting (both files are required inputs).
# Usage: media-release-dex.sh [mapping.txt usage.txt ...]. Default: the :app release build's
# outputs under android/app/build (run :app:assembleRelease first; like merged-manifest-lint
# this gate needs the build, so CI runs it in the android job, not in run-all.sh).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Fully-qualified removable classes, one per line.
REMOVABLE=$(cat <<'EOF'
androidx.media3.datasource.cache.SimpleCache
androidx.media3.datasource.cache.CacheDataSource
androidx.media3.datasource.cache.CacheDataSink
androidx.media3.datasource.cache.CacheWriter
androidx.media3.exoplayer.offline.DownloadManager
androidx.media3.exoplayer.offline.DownloadService
androidx.media3.exoplayer.offline.DownloadHelper
androidx.media3.datasource.HttpEngineDataSource
androidx.media3.datasource.AesCipherDataSource
androidx.media3.datasource.AesCipherDataSink
androidx.media3.datasource.DataSourceInputStream
androidx.media3.muxer.InAppFragmentedMp4Muxer
androidx.media3.exoplayer.util.EventLogger
androidx.media3.database.StandaloneDatabaseProvider
androidx.media3.database.DatabaseProvider
androidx.media3.exoplayer.DefaultRenderersFactory
androidx.media3.exoplayer.image.ImageRenderer
androidx.media3.exoplayer.image.BitmapFactoryImageDecoder
androidx.media3.exoplayer.text.TextRenderer
androidx.media3.exoplayer.metadata.MetadataRenderer
EOF
)

pairs=()
if [ "$#" -gt 0 ]; then
  [ $(( $# % 2 )) -eq 0 ] || fail "usage: media-release-dex.sh [mapping.txt usage.txt]..."
  while [ "$#" -ge 2 ]; do
    pairs+=("$1|$2")
    shift 2
  done
else
  mapping=""
  usage=""
  while IFS= read -r f; do
    case "$f" in
      */mapping/release/mapping.txt) [ -z "$mapping" ] && mapping="$f" ;;
      */mapping/release/usage.txt) [ -z "$usage" ] && usage="$f" ;;
    esac
  done < <(find "$GHOST_ROOT/android/app/build" -type f \( -name 'mapping.txt' -o -name 'usage.txt' \) 2>/dev/null | sort || true)
  [ -n "$mapping" ] || fail "no release mapping.txt under $GHOST_ROOT/android/app/build (run :app:assembleRelease first)"
  [ -n "$usage" ] || fail "no release usage.txt under $GHOST_ROOT/android/app/build (run :app:assembleRelease first)"
  pairs+=("$mapping|$usage")
fi

for pair in ${pairs[@]+"${pairs[@]}"}; do
  mapping="${pair%%|*}"
  usage="${pair#*|}"
  [ -f "$mapping" ] || fail "$mapping: not found"
  [ -f "$usage" ] || fail "$usage: not found"
  removed_reported=0
  while IFS= read -r cls; do
    [ -n "$cls" ] || continue
    simple="${cls##*.}"
    # Kept: named with an obfuscation arrow in mapping.txt. Inner classes of a kept class
    # imply the class itself is kept, so the plain-name check covers them.
    if grep -qE "^$(printf '%s' "$cls" | sed 's/\./\\./g') -> " "$mapping" || \
       grep -qE "^$(printf '%s' "$cls" | sed 's/\./\\./g')\\\$" "$mapping"; then
      fail "$mapping: the removable class $cls is KEPT (G-M10; a kept class means GHOST code references it, S0 V-M14)"
    fi
    if grep -qF "$cls" "$usage"; then
      removed_reported=$((removed_reported + 1))
    fi
  done <<< "$REMOVABLE"
  if [ "$removed_reported" -eq 0 ]; then
    fail "$usage: no removable class appears in the usage report (the file is not R8's usage.txt, or the removable set changed: re-measure, S0-10)"
  fi
  echo "[media-release-dex] checked $mapping + $usage ($removed_reported removable classes confirmed removed)"
done

finish media-release-dex
