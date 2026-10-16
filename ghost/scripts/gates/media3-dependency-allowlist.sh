#!/usr/bin/env bash
# Gate G-M2 (Phase 11 design faza11-media.md §16.1 G-M2, §16.3; slice S7): the Gradle
# dependency rule for Media3. Only these Media3 artifacts may be named by the build:
#   media3-common, -datasource, -database (a hard transitive of -datasource and -exoplayer,
#   S0-5; its classes are G-M1 sinks), -decoder, -extractor, -container, -exoplayer,
#   -transformer, -effect, -muxer (and -ui from Phase 13 — not before).
# Every other media3 artifact is forbidden — media3-session (a session service is a
# background-playback surface §10.2 forbids), -inspector (holds FrameExtractor, G-M3's
# decoder-confinement list), the alternative data sources (-datasource-okhttp, -cronet,
# -rtmp: clearnet), the streaming containers (-exoplayer-hls, -dash, -smoothstreaming,
# -rtsp), -exoplayer-ima, -exoplayer-workmanager, -cast. com.google.android.gms stays
# denied by dependency-allowlist.sh (ADR-06).
# Scanned: every build file and the version catalog under android/ (build outputs excluded).
# The version catalog's media3 pin is asserted to exist so a renamed pin does not silently
# drop the rule's subject. Vacuity: at least one media3 dependency must be present — a
# build that dropped Media3 entirely would otherwise pass a gate about Media3.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

ALLOWED='^(media3-(common|datasource|database|decoder|extractor|container|exoplayer|transformer|effect|muxer))$'

mapfile -t buildfiles < <(find "$GHOST_ROOT/android" -path '*/build' -prune -o -type f \
  \( -name '*.gradle' -o -name '*.gradle.kts' -o -name '*.toml' \) -print 2>/dev/null | sort)
[ "${#buildfiles[@]}" -gt 0 ] || fail "no Gradle build files under $GHOST_ROOT/android"

total=0
for f in ${buildfiles[@]+"${buildfiles[@]}"}; do
  while IFS= read -r line; do
    name="${line#media3-artifact:}"
    total=$((total + 1))
    if ! printf '%s\n' "$name" | grep -qE "$ALLOWED"; then
      fail "${f#"$GHOST_ROOT"/}: media3 artifact not allowlisted by G-M2: $name"
    fi
  done < <(grep -oE 'media3-[a-z0-9-]+' "$f" | sort -u | sed 's/^/media3-artifact:/' || true)
done
if [ "$total" -eq 0 ]; then
  fail "no media3 dependency in any Gradle file (vacuity: the gate must scan something)"
fi

finish media3-dependency-allowlist
