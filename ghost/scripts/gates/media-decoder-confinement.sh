#!/usr/bin/env bash
# Gate G-M3 (Phase 11 design faza11-media.md §16.1 G-M3, §10.3, S0-21; slice S7): decoder
# confinement — no received or picked image byte is parsed by a native decoder in the main
# process; video is parsed only by Media3's fMP4 extractor and decoded only by MediaCodec.
# Three rules over the production sources (android/*/src/main, src/release, src/gate; test
# sources are not read):
#
# (1) SOURCE RULE: the platform decoder and thumbnailer APIs are referenced only from
#     org.ghost.media.sandbox (the isolated-process service, the only package that may name
#     them). Matched as the qualified platform form (`android.media.ImageDecoder`,
#     `android.graphics.BitmapFactory`, ...) anywhere, and as the bare name in any file that
#     imports the platform class — so GHOST's own `org.ghost.media.send.ImageDecoder` port
#     (the sandbox seam's name, sanctioned by §9.2) is not a hit: it is never imported from
#     android.media. The dotted member forms are banned outside the sandbox outright:
#     `.loadThumbnail(`, `.setImageURI(`, `Drawable.createFromStream/Path`,
#     `Icon.createWithContentUri/FilePath/Data`.
#     Banned names: ImageDecoder, BitmapFactory, BitmapRegionDecoder, ExifInterface,
#     MediaMetadataRetriever, HeifDecoder, ThumbnailUtils, AnimatedImageDrawable, Movie,
#     FrameExtractor (media3-inspector's; the artifact is G-M2-forbidden, this is the source
#     backstop).
#     Exact exemptions, counted (F-S7 finding): PickedVideo.kt holds the platform metadata
#     retriever ×5 — §6.1's container probes (duration, display rotation) of a picked source
#     parse the container before any byte is re-encoded. G-M3's letter names the retriever
#     for the sandbox alone; the review may demand the Media3-extractor rewrite (different
#     rotation semantics across API levels is why S5 chose it).
#     CalibrationFrameProbe.kt holds the retriever ×4 only for the internally generated colour-grid
#     calibration stream; no picked or received byte reaches it. Its call site is CalibrationExport.
# (2) CONFIGURATION RULE (S0-21): every Media3 instance GHOST builds is built with GHOST's
#     factories — the default renderers/extractors/media-source factories and the bitmap
#     loaders are refused everywhere in GHOST sources, and `ExoPlayer.Builder` is named only
#     in org.ghost.media.play (GhostPlayer is the one builder). `Transformer` itself is G-M1's
#     rule (GhostTranscoder alone).
# (3) SHAPE ASSERTIONS over GhostPlayer.kt, so a quiet deletion fails the gate: the fMP4
#     extractor is built with FLAG_READ_MFRA_FOR_SEEK_MAP (without it the seek map is
#     unseekable and a seek replays from the start — MC-M24's mutation), the renderers
#     factory names MediaCodecVideoRenderer and MediaCodecAudioRenderer, the builder sets
#     setUsePlatformDiagnostics(false), and Media3's logger is switched off.
# The bytecode half of §16.1's G-M3 (javap -c over the release variant's org.ghost classes, so
# an alias or a helper call cannot slip past a name list) runs in the CI android job over the
# built release classes; it is not runnable in the source-only run-all sweep (F-S7 pending
# note, with G-M10's release-dex check covering the same classes in the same job). The source
# gate's own forward-looking blind spots, recorded per F-S7-3 as that half's to-cover: (i) the
# platform's other decode entry points — MediaExtractor, MediaPlayer, MediaParser — name no
# decoder class this gate bans, so a future call would pass the source sweep and is caught only
# by the bytecode name list; (ii) a renderer built directly (an ImageRenderer or a
# MediaCodecVideoRenderer constructed outside GhostPlayer's factory in a shape the source
# assertions do not name) — the shape assertions pin GhostPlayer.kt's own text, the bytecode
# half pins what the tree actually links.
# Vacuity: the sweep must read at least one file; the sandbox package must exist.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
TMP="$(mktemp -d)"
trap 'rc=$?; rm -rf "$TMP"; exit $rc' EXIT

mapfile -t files < <({ android_main_files; android_gate_files; } | sort -u)
[ "${#files[@]}" -gt 0 ] || fail "no Android production sources under $GHOST_ROOT/android"
printf '%s\n' ${files[@]+"${files[@]}"} > "$TMP/files"

# Banned platform decoder names (bare-name matching is import-driven; see header).
BANNED_NAMES='ImageDecoder|BitmapFactory|BitmapRegionDecoder|ExifInterface|MediaMetadataRetriever|HeifDecoder|ThumbnailUtils|AnimatedImageDrawable|Movie|FrameExtractor'

sandbox_hits=0
for f in ${files[@]+"${files[@]}"}; do
  case "$f" in
    */org/ghost/media/sandbox/*) sandbox_hits=$((sandbox_hits + 1)); continue ;;
  esac
  base="$(basename "$f")"
  # Qualified platform forms, anywhere outside the sandbox.
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    # The counted exemption's import line (see header): PickedVideo.kt's metadata retriever.
    case "$base:$hit" in
      PickedVideo.kt:*MediaMetadataRetriever*)
        n=$(grep -cE "(^|[^A-Za-z0-9_])MediaMetadataRetriever($|[^A-Za-z0-9_])" "$f" || true)
        [ "$n" = "5" ] && continue
        ;;
      CalibrationFrameProbe.kt:*MediaMetadataRetriever*)
        n=$(grep -cE "(^|[^A-Za-z0-9_])MediaMetadataRetriever($|[^A-Za-z0-9_])" "$f" || true)
        [ "$n" = "4" ] && continue
        ;;
    esac
    fail "${f#"$GHOST_ROOT"/}: $hit (G-M3: a platform decoder API outside org.ghost.media.sandbox)"
  done < <(grep -nE "android\.(media|graphics|graphics\.drawable|provider)\.($BANNED_NAMES)($|[^A-Za-z0-9_])" "$f" 2>/dev/null || true)
  # Bare names in files that import the platform class.
  imported=$(grep -oE "^import android\.(media|graphics|graphics\.drawable|provider)\.($BANNED_NAMES)($|[^A-Za-z0-9_])" "$f" 2>/dev/null | sed -E 's/^import android\.(media|graphics|graphics\.drawable|provider)\.//; s/[^A-Za-z0-9_].*$//' | sort -u || true)
  if [ -n "$imported" ]; then
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      # The counted exemption: PickedVideo.kt's metadata retriever (see header).
      if [ "$base" = "PickedVideo.kt" ] && [ "$name" = "MediaMetadataRetriever" ]; then
        n=$(grep -cE "(^|[^A-Za-z0-9_])MediaMetadataRetriever($|[^A-Za-z0-9_])" "$f" || true)
        if [ "$n" = "5" ]; then continue; fi
      fi
      if [ "$base" = "CalibrationFrameProbe.kt" ] && [ "$name" = "MediaMetadataRetriever" ]; then
        n=$(grep -cE "(^|[^A-Za-z0-9_])MediaMetadataRetriever($|[^A-Za-z0-9_])" "$f" || true)
        if [ "$n" = "4" ]; then continue; fi
      fi
      while IFS= read -r hit; do
        [ -n "$hit" ] || continue
        fail "${f#"$GHOST_ROOT"/}: $hit (G-M3: $name is imported from the platform outside the sandbox)"
      done < <(grep -nE "(^|[^A-Za-z0-9_])$name($|[^A-Za-z0-9_])" "$f" 2>/dev/null || true)
    done <<< "$imported"
  fi
  # Dotted member forms outside the sandbox.
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    fail "${f#"$GHOST_ROOT"/}: $hit (G-M3: platform thumbnailer outside org.ghost.media.sandbox)"
  done < <(grep -nE "\.loadThumbnail\(|\.setImageURI\(|Drawable\.createFrom|Icon\.createWith(ContentUri|FilePath|Data)" "$f" 2>/dev/null || true)
  # Configuration rule: Media3's defaults are refused everywhere in GHOST sources.
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    fail "${f#"$GHOST_ROOT"/}: $hit (G-M3 configuration rule: Media3's default factories are refused, S0-21)"
  done < <(grep -nE "(^|[^A-Za-z0-9_])(DefaultRenderersFactory|DefaultExtractorsFactory|DefaultMediaSourceFactory|DataSourceBitmapLoader)($|[^A-Za-z0-9_])" "$f" 2>/dev/null || true)
  case "$f" in
    */org/ghost/media/play/*) : ;; # GhostPlayer names the builder, by design
    *)
      while IFS= read -r hit; do
        [ -n "$hit" ] || continue
        fail "${f#"$GHOST_ROOT"/}: $hit (G-M3 configuration rule: the player is built only through GhostPlayer)"
      done < <(grep -nE "ExoPlayer\.Builder" "$f" 2>/dev/null || true)
      ;;
  esac
done
[ "$sandbox_hits" -gt 0 ] || fail "org.ghost.media.sandbox has no production sources (vacuity)"

# Shape assertions over the one player factory.
PLAYER=""
for f in ${files[@]+"${files[@]}"}; do
  case "$f" in */org/ghost/media/play/GhostPlayer.kt) PLAYER="$f" ;; esac
done
[ -n "$PLAYER" ] || fail "org.ghost.media.play.GhostPlayer.kt is missing"
assert_shape() { # regex|message
  if ! grep -qE "$1" "$PLAYER"; then
    fail "GhostPlayer.kt: $2"
  fi
}
assert_shape 'FragmentedMp4Extractor\.FLAG_READ_MFRA_FOR_SEEK_MAP' "the fMP4 extractor must be built with FLAG_READ_MFRA_FOR_SEEK_MAP (MC-M24's mutation seeks back to the start without it)"
assert_shape '(^|[^A-Za-z0-9_])MediaCodecVideoRenderer($|[^A-Za-z0-9_])' "the renderers factory must build a MediaCodecVideoRenderer (exactly one video renderer)"
assert_shape '(^|[^A-Za-z0-9_])MediaCodecAudioRenderer($|[^A-Za-z0-9_])' "the renderers factory must build a MediaCodecAudioRenderer (exactly one audio renderer)"
assert_shape 'setUsePlatformDiagnostics\(false\)' "the player must setUsePlatformDiagnostics(false) (§10.2)"
assert_shape 'Log\.setLogLevel\(Log\.LOG_LEVEL_OFF\)' "Media3's logger must be switched off (§10.2)"

finish media-decoder-confinement
