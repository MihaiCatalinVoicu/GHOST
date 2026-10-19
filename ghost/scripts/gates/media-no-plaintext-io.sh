#!/usr/bin/env bash
# Gate G-M1 (Phase 11 design faza11-media.md §16.1 G-M1, §10.3; slice S7): no plaintext media
# at rest — two rules over the production sources (every android/*/src/main, plus src/release
# and the gate build type's src/gate; test sources are not read).
#
# (a) SINKS: no source names a plaintext-persistence or cleartext-media API. The design's
#     list, matched as whole words (class names) or after a dot (the Kotlin property and
#     method forms, so a parameter named `cacheDir` is not a hit — §16.1's own reading):
#     Media3's caching/download stack (SimpleCache, CacheDataSource/Sink, CacheWriter,
#     DownloadManager/Service/Helper), Media3's clearnet and file data sources
#     (DefaultDataSource, DefaultHttpDataSource, HttpEngineDataSource, UdpDataSource,
#     FileDataSource), AesCipherDataSource/Sink, InAppMp4Muxer (Transformer's default muxer),
#     MediaStore (the provider, matched qualified or in use — `MediaStoreException` is not
#     `MediaStore.`), MediaScannerConnection, the external/temp/cache sinks (getExternalFilesDir(s),
#     externalCacheDir, getExternalCacheDir(s), getExternalMediaDirs,
#     Environment.getExternalStorage, createTempFile, getCacheDir()/.cacheDir,
#     getCodeCacheDir()/.codeCacheDir, openFileOutput), FileProvider, ACTION_SEND, ClipData,
#     BigPictureStyle, setLargeIcon, MediaSession, takePersistableUriPermission (S0-7),
#     StandaloneDatabaseProvider/DatabaseProvider (S0-5), and Transformer — matched as an
#     import of the class or a use (`Transformer.Builder`, `Transformer(`; a comment that
#     names it in prose is not a use) — only GhostTranscoder.kt may show those.
#     A line is a line: a comment that names a banned API in its code shape fails too, on
#     purpose (the messaging-no-network.sh reading — say it in the design document).
#     Exact exemptions, counted (a use added or removed fails the gate):
#       GhostTranscoder.kt `.cacheDir` ×3 — §8.3 point 5(d)'s encoder calibration writes the
#       bundled GHOST-generated colour-grid clip and deletes it in a finally, and the two
#       "never-written" muxer offered paths exist to prove Transformer writes nothing (V-M1).
#       F-S7 finding: the review may demand an in-memory calibration source instead.
# (b) WRITERS: a file-writing call appears only in a file listed in
#     file-writer-allowlist.txt, and the file holds exactly the listed count of that writer
#     (both directions — a new writer in a listed file fails too). The writers: FileOutputStream,
#     RandomAccessFile, FileWriter, PrintWriter, Files.write/writeString/newOutputStream/
#     newBufferedWriter/copy/move (the `java.nio.file.Files` forms — `CiphertextFiles.write`
#     in a comment is not `Files.write`), FileChannel.open, AsynchronousFileChannel.open,
#     Files.newByteChannel, AtomicFile, File.writeBytes/
#     writeText/appendBytes/appendText/outputStream()/bufferedWriter()/printWriter()/copyTo()/
#     copyRecursively(), ContentResolver.openOutputStream, openFileDescriptor/
#     openAssetFileDescriptor (any mode; the "r"-only form would need a parser to grade),
#     ParcelFileDescriptor.open, openFileOutput.
#     The count claim, narrowed (F-S7 review): the counts are line-granular — one regex over
#     the whole file, not a parse of the option list — so `FileChannel.open` ×3 covers the
#     READ-only directory sync, and the `(WRITE)` in the two new writers' prose is the banned
#     shape, not a graded option: a READ-only `AsynchronousFileChannel.open` or
#     `Files.newByteChannel` in an allowlisted file counts against the row like any other.
#     A write-option-less open in an unlisted file still fails (the name is banned outside
#     the allowlist).
# What a text gate cannot see: a name built at run time, a writer reached through a helper
# this list does not name. Those are the reviewer's (§16.1's note is the same).
# Vacuity: android/media/src/main must hold at least one source.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
# The writer allowlist is global (real tree paths); self-test fixtures override it with a
# fixture-local table (GHOST_WRITER_ALLOWLIST) so a fixture tree can be clean.
ALLOWLIST="${GHOST_WRITER_ALLOWLIST:-$GATES_DIR/file-writer-allowlist.txt}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# (a) sinks: one label-regex per line; the regex may not contain a newline.
cat > "$TMP/sinks" <<'EOF'
simple-cache|(^|[^A-Za-z0-9_])SimpleCache($|[^A-Za-z0-9_])
cache-data-source|(^|[^A-Za-z0-9_])CacheDataSource($|[^A-Za-z0-9_])
cache-data-sink|(^|[^A-Za-z0-9_])CacheDataSink($|[^A-Za-z0-9_])
cache-writer|(^|[^A-Za-z0-9_])CacheWriter($|[^A-Za-z0-9_])
download-manager|(^|[^A-Za-z0-9_])DownloadManager($|[^A-Za-z0-9_])
download-service|(^|[^A-Za-z0-9_])DownloadService($|[^A-Za-z0-9_])
download-helper|(^|[^A-Za-z0-9_])DownloadHelper($|[^A-Za-z0-9_])
default-data-source|(^|[^A-Za-z0-9_])DefaultDataSource($|[^A-Za-z0-9_])
default-http-data-source|(^|[^A-Za-z0-9_])DefaultHttpDataSource($|[^A-Za-z0-9_])
httpengine-data-source|(^|[^A-Za-z0-9_])HttpEngineDataSource($|[^A-Za-z0-9_])
udp-data-source|(^|[^A-Za-z0-9_])UdpDataSource($|[^A-Za-z0-9_])
aes-cipher-data-source|(^|[^A-Za-z0-9_])AesCipherDataSource($|[^A-Za-z0-9_])
aes-cipher-data-sink|(^|[^A-Za-z0-9_])AesCipherDataSink($|[^A-Za-z0-9_])
file-data-source|(^|[^A-Za-z0-9_])FileDataSource($|[^A-Za-z0-9_])
in-app-muxer|(^|[^A-Za-z0-9_])InAppMp4Muxer($|[^A-Za-z0-9_])
mediastore|android\.provider\.MediaStore
mediastore|(^|[^A-Za-z0-9_.])MediaStore[.(\[:]
mediascanner|(^|[^A-Za-z0-9_])MediaScannerConnection($|[^A-Za-z0-9_])
external-files-dir|\.getExternalFilesDirs?\(
external-cache-dir|\.externalCacheDir($|[^A-Za-z0-9_])|\.getExternalCacheDirs?\(
external-media-dirs|\.getExternalMediaDirs\(
environment-external|(^|[^A-Za-z0-9_])Environment\.getExternalStorage
create-temp-file|(^|[^A-Za-z0-9_])createTempFile($|[^A-Za-z0-9_])
cache-dir|\.cacheDir($|[^A-Za-z0-9_])|\.getCacheDir\(\)
code-cache-dir|\.codeCacheDir($|[^A-Za-z0-9_])|\.getCodeCacheDir\(\)
open-file-output|\.openFileOutput\(
file-provider|(^|[^A-Za-z0-9_])FileProvider($|[^A-Za-z0-9_])
action-send|(^|[^A-Za-z0-9_])ACTION_SEND($|[^A-Za-z0-9_])
clip-data|(^|[^A-Za-z0-9_])ClipData($|[^A-Za-z0-9_])
big-picture-style|(^|[^A-Za-z0-9_])BigPictureStyle($|[^A-Za-z0-9_])
set-large-icon|\.setLargeIcon\(
media-session|(^|[^A-Za-z0-9_])MediaSession($|[^A-Za-z0-9_])
persistable-permission|(^|[^A-Za-z0-9_])takePersistableUriPermission($|[^A-Za-z0-9_])
standalone-database-provider|(^|[^A-Za-z0-9_])StandaloneDatabaseProvider($|[^A-Za-z0-9_])
database-provider|(^|[^A-Za-z0-9_])DatabaseProvider($|[^A-Za-z0-9_])
transformer|import androidx\.media3\.transformer\.Transformer($|[^A-Za-z0-9_])|(^|[^A-Za-z0-9_])Transformer[.({]
EOF

# (b) writers: one label-regex per line.
cat > "$TMP/writers" <<'EOF'
file-output-stream|(^|[^A-Za-z0-9_])FileOutputStream($|[^A-Za-z0-9_])
random-access-file|(^|[^A-Za-z0-9_])RandomAccessFile($|[^A-Za-z0-9_])
file-writer|(^|[^A-Za-z0-9_])FileWriter($|[^A-Za-z0-9_])
print-writer|(^|[^A-Za-z0-9_])PrintWriter($|[^A-Za-z0-9_])
files-write|(^|[^A-Za-z0-9_.])Files\.write(String)?($|[^A-Za-z0-9_])
files-new-output-stream|(^|[^A-Za-z0-9_.])Files\.newOutputStream($|[^A-Za-z0-9_])
files-new-buffered-writer|(^|[^A-Za-z0-9_.])Files\.newBufferedWriter($|[^A-Za-z0-9_])
files-copy|(^|[^A-Za-z0-9_.])Files\.copy($|[^A-Za-z0-9_])
files-move|(^|[^A-Za-z0-9_.])Files\.move($|[^A-Za-z0-9_])
file-channel-open|(^|[^A-Za-z0-9_])FileChannel\.open($|[^A-Za-z0-9_])
async-file-channel-open|(^|[^A-Za-z0-9_])AsynchronousFileChannel\.open($|[^A-Za-z0-9_])
files-new-byte-channel|(^|[^A-Za-z0-9_.])Files\.newByteChannel($|[^A-Za-z0-9_])
atomic-file|(^|[^A-Za-z0-9_])AtomicFile($|[^A-Za-z0-9_])
file-write-bytes|\.writeBytes\(
file-write-text|\.writeText\(
file-append-bytes|\.appendBytes\(
file-append-text|\.appendText\(
file-output-stream-fn|\.outputStream\(\)
file-buffered-writer-fn|\.bufferedWriter\(
file-print-writer-fn|\.printWriter\(
file-copy-to|\.copyTo\(
file-copy-recursively|\.copyRecursively\(
open-output-stream|\.openOutputStream\(
open-file-descriptor|\.openFileDescriptor\(|\.openAssetFileDescriptor\(
pfd-open|(^|[^A-Za-z0-9_])ParcelFileDescriptor\.open($|[^A-Za-z0-9_])
EOF

# The exact, counted sink exemptions: module-relative-path|label|expected-times — the path
# is relative to android/ (F-S7 review: keyed by path, not basename, so a same-named file in
# another module does not inherit the exemption).
cat > "$TMP/sink-exemptions" <<'EOF'
media/src/main/kotlin/org/ghost/media/send/GhostTranscoder.kt|cache-dir|3
media/src/main/kotlin/org/ghost/media/send/GhostTranscoder.kt|transformer|6
# Phase 13 S0b (design faza13-ux.md §13.1 G-U2 × G-M1's shared exemption): the one ClipData of
# the UI is the sensitive clipboard writer's own labelled clip — exactly the sink G-U2 confines
# to SensitiveClipboard.kt, never plaintext IO of media bytes.
ui/src/main/kotlin/org/ghost/ui/protect/SensitiveClipboard.kt|clip-data|3
# Phase 13 S6 (design faza13-ux.md §6.6, V-U34/FX-1): SystemIntents builds the platform
# photo-picker ACTION (MediaStore.ACTION_PICK_IMAGES on API 33+) — an intent constant the
# design prescribes, not provider IO; the picked bytes are read by :app through the resolver,
# never written to any MediaStore surface.
ui/src/main/kotlin/org/ghost/ui/platform/SystemIntents.kt|mediastore|1
EOF

mapfile -t files < <({ android_main_files; android_gate_files; } | sort -u)
[ "${#files[@]}" -gt 0 ] || fail "no Android production sources under $GHOST_ROOT/android"
if [ ! -d "$GHOST_ROOT/android/media/src/main" ]; then
  fail "android/media/src/main is missing (vacuity: the gate must scan something)"
fi
printf '%s\n' ${files[@]+"${files[@]}"} > "$TMP/files"

# One awk pass per rule over every file: prints "path|label|count" and "path|label|line:text".
run_rule() { # spec-file
  awk -v specfile="$1" -v filelist="$TMP/files" '
    function load_specs(   n, i, line, pos) {
      n = 0
      while ((getline line < specfile) > 0) {
        if (line == "") continue
        pos = index(line, "|")
        n++
        label[n] = substr(line, 1, pos - 1)
        re[n] = substr(line, pos + 1)
      }
      count = n
      close(specfile)
    }
    BEGIN {
      load_specs()
      while ((getline f < filelist) > 0) filecount++
      close(filelist)
    }
    FNR == 1 {
      fileno++
      base = FILENAME
      sub(/^.*\//, "", base)
    }
    {
      for (i = 1; i <= count; i++) {
        if ($0 ~ re[i]) {
          hits[FILENAME "|" label[i]]++
          printf "%s|%s|%d:%s\n", FILENAME, label[i], FNR, $0
        }
      }
    }
    END {
      for (k in hits) {
        split(k, a, "|")
        printf "COUNT|%s|%s|%d\n", a[1], a[2], hits[k]
      }
      printf "SCANNED|%d\n", fileno + 0
    }
  ' $(cat "$TMP/files")
}

# ---- (a) sinks -----------------------------------------------------------
run_rule "$TMP/sinks" > "$TMP/sink-out" 2>/dev/null || true
# Group counts: path|label -> n (COUNT lines), then judge.
while IFS='|' read -r kind a b c; do
  if [ "$kind" = "SCANNED" ]; then
    [ "$a" = "${#files[@]}" ] || fail "the sink sweep read $a of ${#files[@]} files"
    continue
  fi
  [ "$kind" = "COUNT" ] || continue
  path="$a"; label="$b"; n="$c"
  rel="${path#"$GHOST_ROOT"/android/}"
  exempted=0
  while IFS='|' read -r eb el ex; do
    if [ "$rel" = "$eb" ] && [ "$el" = "$label" ] && [ "$n" = "$ex" ]; then exempted=1; fi
  done < "$TMP/sink-exemptions"
  if [ "$exempted" = 0 ]; then
    while IFS='|' read -r p l line; do
      [ -n "$p" ] || continue
      fail "${p#"$GHOST_ROOT"/}: $line (G-M1 sink: $label)"
    done < <(grep -F "|$label|" "$TMP/sink-out" | grep -v '^COUNT|' || true)
  fi
done < "$TMP/sink-out"

# ---- (b) writers ----------------------------------------------------------
run_rule "$TMP/writers" > "$TMP/writer-out" 2>/dev/null || true

# The allowlist rows: path|regex|times.
ALLOWROWS=()
while IFS='|' read -r kind path re times _why; do
  [ "$kind" = "file" ] || continue
  ALLOWROWS+=("$path|$re|$times")
  if [ ! -f "$GHOST_ROOT/android/$path" ]; then
    fail "file-writer-allowlist.txt lists $path, which does not exist"
  fi
done < "$ALLOWLIST"

# Every observed writer count must be an allowlisted (path, regex) pair: an allowlist row of the
# same path whose regex matches one of the label's hit lines.
while IFS='|' read -r kind a b c; do
  if [ "$kind" = "SCANNED" ]; then continue; fi
  [ "$kind" = "COUNT" ] || continue
  path="${a#"$GHOST_ROOT"/android/}"; label="$b"
  listed=0
  for row in ${ALLOWROWS[@]+"${ALLOWROWS[@]}"}; do
    kpath="${row%%|*}"
    rest="${row#*|}"
    kre="${rest%%|*}"
    [ "$kpath" = "$path" ] || continue
    if grep -E "^[^|]*\|[^|]*\|.*$kre" "$TMP/writer-out" | grep -v '^COUNT|' | grep -q "^${a}|${b}|"; then
      listed=1
    fi
  done
  if [ "$listed" = 0 ]; then
    while IFS='|' read -r p l line; do
      [ -n "$p" ] || continue
      fail "${p#"$GHOST_ROOT"/}: $line (G-M1 writer: $label not in file-writer-allowlist.txt)"
    done < <(grep "^${a}|${b}|" "$TMP/writer-out" | grep -v '^COUNT|' || true)
  fi
done < "$TMP/writer-out"

# Both directions of the counts: every allowlist row must be observed exactly.
for row in ${ALLOWROWS[@]+"${ALLOWROWS[@]}"}; do
  kpath="${row%%|*}"
  rest="${row#*|}"
  kre="${rest%%|*}"
  want="${rest##*|}"
  got=$(grep -cE "$kre" "$GHOST_ROOT/android/$kpath" 2>/dev/null || true)
  if [ "$got" != "$want" ]; then
    fail "android/$kpath: G-M1 writer allowlist expects '$kre' ×$want, found ×$got"
  fi
done

finish media-no-plaintext-io
