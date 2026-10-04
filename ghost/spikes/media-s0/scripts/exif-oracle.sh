#!/usr/bin/env bash
# T43 / X-M13 oracle over pulled outputs: ExifTool's full tag dump (-a -G1 -s) of every file, then
# every tag that is NOT in the structural allowlist below, then a canary search (ASCII, UTF-16LE,
# UTF-16BE) through mediatool. A canonical output must show no tag outside the allowlist and no
# canary. Evidence tooling for docs/design/faza11-s0-evidence.md (V-M3, V-M6, V-M17, V-M24).
#   EXIFTOOL='perl /path/Image-ExifTool-13.55/exiftool' scripts/exif-oracle.sh <file>...
# The allowlist is what a re-encoded file always carries (size, dimensions, coding, container
# structure with constant values); the [System] group is the host file system's, not the file's.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exiftool="${EXIFTOOL:?set EXIFTOOL to the ExifTool 13.55 command}"
tool="${MEDIATOOL:?set MEDIATOOL to the host mediatool binary}"
allow='^\[(ExifTool|System)\]|^\[File\] +(FileType|FileTypeExtension|MIMEType|ImageWidth|ImageHeight|EncodingProcess|BitsPerSample|ColorComponents|YCbCrSubSampling) |^\[Composite\] +(ImageSize|Megapixels|Rotation|AvgBitrate) |^\[QuickTime\] +(MajorBrand|MinorVersion|CompatibleBrands|MovieHeaderVersion|MovieFragmentSequence|CreateDate|ModifyDate|TimeScale|Duration|PreferredRate|PreferredVolume|MatrixStructure|PreviewTime|PreviewDuration|PosterTime|SelectionTime|SelectionDuration|CurrentTime|NextTrackID|MediaDataSize|MediaDataOffset) |^\[Track[0-9]+\] +(TrackHeaderVersion|TrackCreateDate|TrackModifyDate|TrackID|TrackDuration|TrackLayer|TrackVolume|MatrixStructure|ImageWidth|ImageHeight|MediaHeaderVersion|MediaCreateDate|MediaModifyDate|MediaTimeScale|MediaDuration|MediaLanguageCode|HandlerType|HandlerDescription|GraphicsMode|OpColor|Balance|CompressorID|SourceImageWidth|SourceImageHeight|XResolution|YResolution|BitDepth|PixelAspectRatio|ColorProfiles|ColorPrimaries|TransferCharacteristics|MatrixCoefficients|VideoFullRangeFlag|AudioFormat|AudioChannels|AudioBitsPerSample|AudioSampleRate|SampleSizes|VideoFrameRate) '
for f in "$@"; do
  echo "=== $f ($(wc -c < "$f") B, sha256 $(sha256sum "$f" | cut -c1-64))"
  dump="$($exiftool -a -G1 -s "$f" 2>&1 || true)"
  printf '%s\n' "$dump" | sed 's/^/  /'
  extra="$(printf '%s\n' "$dump" | grep -v -E "$allow" | grep -v -E '^(Warning|Error)' || true)"
  if [ -n "$extra" ]; then
    echo "  -- tags outside the structural allowlist: $(printf '%s\n' "$extra" | wc -l)"
    printf '%s\n' "$extra" | sed 's/^/  !! /'
  else
    echo "  -- tags outside the structural allowlist: 0"
  fi
  "$tool" canary "$f" GHOSTCANARYS0 "2026:09:25" "46.77" "23.62" "com.android" "GHOST-S0" | sed 's/^/  /'
done
