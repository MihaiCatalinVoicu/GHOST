#!/usr/bin/env bash
# Gate G-D2 (Phase 14 design faza14-distribution.md §12.1, §6.2/§6.3; decision D11): the
# builder's pins are the single source of every toolchain byte. Rules:
#   1. The Dockerfile's FROM is the `image` line's pinned ubuntu digest, and the pins and the
#      Dockerfile agree in BOTH directions on the downloads: every digest recorded in
#      pins.txt (sha256 and the Android sha1 values) is an ARG in the Dockerfile, and every
#      `ARG *_SHA(256|1)` value in the Dockerfile is recorded in pins.txt.
#   2. Every download URL in the Dockerfile (comment lines stripped) names a file whose
#      spelling sits in pins.txt — no unpinned archive may enter the image.
#   3. The apt pin versions in the Dockerfile's install block equal the apt section of
#      pins.txt (both directions). The apt section is the lines whose third field is the
#      `apt pin (Dockerfile)` marker.
#   4. No sdkmanager or rustup runs in infra/builder (the Dockerfile documents their absence
#      in comments and prose — only command usage fails).
#   5. The named toolchain versions agree with their pin: rust-toolchain.toml's channel with
#      pins.txt's rust line, gradle-wrapper.properties' version and distributionSha256Sum with
#      the gradle line, scripts/install-protoc.sh's VERSION/SHA256 pair (present and, when
#      pins.txt gains a protoc line, equal to it), scripts/build-native.sh's cargo-ndk
#      version with the cargo-ndk line, and the NDK/SDK archive spellings with the android_*
#      lines.
#   6. No -march/-mtune/target-cpu=native in any build file, and no --cpus in
#      scripts/release/build-release.sh (the processor count is pinned by the image's
#      JAVA_TOOL_OPTIONS/Gradle workers/CARGO_BUILD_JOBS, not Docker's flag).
#
# Documented as manual (not mechanized here): ci.yml's agreement row — this checkout carries
# no .github/workflows (the CI definitions live with the runner); when ci.yml lands in the
# tree, its RUST/NDK/SDK/JDK lines join rule 5 by the same exact-string method.
#
# Runs in run-all.sh (reads files only). Self-test hooks, honoured for fixture roots only
# (a GHOST_ROOT other than this repository's ghost/): GHOST_BP_ROOT names the scanned root
# (the fixtures mirror ghost/'s layout).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
ROOT="${GHOST_BP_ROOT:-$GHOST_ROOT}"
REAL_ROOT="$(cd "$GATES_DIR/../.." && pwd -P)"
if [ -n "${GHOST_BP_ROOT:-}" ] && [ "$(cd "$ROOT" && pwd -P)" = "$REAL_ROOT" ]; then
  echo "GHOST_BP_ROOT is a self-test hook for fixture roots only" >&2
  exit 2
fi
for need in infra/builder/Dockerfile infra/builder/pins.txt rust-toolchain.toml \
  android/gradle/wrapper/gradle-wrapper.properties scripts/install-protoc.sh \
  scripts/build-native.sh scripts/release/build-release.sh; do
  [ -f "$ROOT/$need" ] || { echo "G-D2: $need missing under $ROOT" >&2; exit 2; }
done

DOCKERFILE="$ROOT/infra/builder/Dockerfile"
PINS="$ROOT/infra/builder/pins.txt"
# Full-line comments blanked (line numbers preserved); the scanned files carry no '#' inside
# real lines, and the sdkmanager/rustup rule must not trip on the Dockerfile's prose about
# their absence.
nocomment() { grep -vE '^[[:space:]]*#' "$1"; }

# Rule 1: FROM digest, and the pins <-> ARG digests, both directions.
from_line="$(grep -E '^FROM ' "$DOCKERFILE" | head -1)"
image_pin="$(awk '/^image /{print $2; exit}' "$PINS")"
[ -n "$image_pin" ] || fail "pins.txt has no image line"
[ "$from_line" = "FROM $image_pin" ] || fail "Dockerfile FROM '$from_line' is not the pinned image '$image_pin'"

pins_digests="$(nocomment "$PINS" | grep -oE 'sha256 [0-9a-f]{64}|sha1 [0-9a-f]{40}' | awk '{print $2}' | sort -u)"
docker_args="$(grep -E '^ARG [A-Z0-9_]*(SHA256|SHA1)=' "$DOCKERFILE" | sed -E 's/^ARG [A-Z0-9_]+=//' | sort -u)"
while IFS= read -r d; do
  [ -n "$d" ] || continue
  grep -qx "$d" <<< "$docker_args" || fail "pins.txt records $d, but no Dockerfile ARG carries it (a pin the image does not verify)"
done <<< "$pins_digests"
while IFS= read -r d; do
  [ -n "$d" ] || continue
  grep -qx "$d" <<< "$pins_digests" || fail "the Dockerfile verifies $d, but pins.txt does not record it (a download the single source does not name)"
done <<< "$docker_args"

# Rule 2: every download is digest-verified in its own layer: a RUN paragraph that curls a
# URL must sha(256|1)sum -c an ARG in the same paragraph (rules 1's both directions then tie
# every ARG to pins.txt — no unpinned archive can enter the image).
paragraph="$(nocomment "$DOCKERFILE" | awk 'BEGIN{RS="";FS="\n"} {out=""; for(i=1;i<=NF;i++) out=out $i " "; print out}')"
while IFS= read -r block; do
  [ -n "$block" ] || continue
  if grep -q 'curl .*http' <<< "$block"; then
    grep -qE 'sha(256|1)sum -c' <<< "$block" || fail "a Dockerfile layer downloads without a digest check: $(printf '%s' "$block" | head -1)"
  fi
done <<< "$paragraph"

# Rule 3: the apt pins, both directions. pins.txt's apt lines carry the `apt pin (Dockerfile)`
# marker in their third field; the Dockerfile's install block pins name=version.
apt_block="$(nocomment "$DOCKERFILE" | sed -n '/apt-get install/,/rm -rf \/var\/lib\/apt/p' | grep -oE '[a-z][a-z0-9+-]*=[^[:space:]\\]+' | sort -u)"
apt_pins="$(awk '$3 ~ /^apt/{print $1"="$2}' "$PINS" | sort -u)"
while IFS= read -r p; do
  [ -n "$p" ] || continue
  grep -qx "$p" <<< "$apt_block" || fail "pins.txt apt-pins $p, but the Dockerfile's install block pins otherwise"
done <<< "$apt_pins"
while IFS= read -r p; do
  [ -n "$p" ] || continue
  awk -v n="${p%%=*}" '$3 ~ /^apt/ && $1 == n {found=1} END {exit !found}' "$PINS" \
    || fail "the Dockerfile apt-pins $p, but pins.txt records no such package"
done <<< "$apt_block"

# Rule 4: no sdkmanager/rustup as commands in infra/builder.
while IFS= read -r f; do
  [ -n "$f" ] || continue
  hits="$(nocomment "$f" | grep -nE '(^|[;&|[:space:]])(sdkmanager|rustup)([[:space:]]|$)' || true)"
  [ -z "$hits" ] || while IFS= read -r line; do fail "${f#"$ROOT"/}:$line"; done <<< "$hits"
done < <(find "$ROOT/infra/builder" -maxdepth 1 -type f \( -name 'Dockerfile' -o -name '*.sh' \) -print 2>/dev/null | sort)

# Rule 5: the named toolchain versions agree with their pins.
channel="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$ROOT/rust-toolchain.toml" | head -1)"
[ -n "$channel" ] || fail "rust-toolchain.toml carries no channel"
awk -v c="$channel" '/^rust /{if (index($0, c)) found=1} END{exit !found}' "$PINS" || fail "pins.txt's rust line does not name the toolchain channel $channel"

WRAP="$ROOT/android/gradle/wrapper/gradle-wrapper.properties"
gradle_sum="$(awk -F= '/^distributionSha256Sum=/{print $2; exit}' "$WRAP")"
gradle_ver="$(awk -F= '/^distributionUrl=/{print $2; exit}' "$WRAP" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
[ -n "$gradle_ver" ] && [ -n "$gradle_sum" ] || fail "gradle-wrapper.properties carries no version/sum"
awk -v v="$gradle_ver" '/^gradle /{if (index($0, v)) found=1} END{exit !found}' "$PINS" || fail "pins.txt's gradle line does not name $gradle_ver"
awk -v s="$gradle_sum" '/^gradle /{if (index($0, s)) found=1} END{exit !found}' "$PINS" || fail "pins.txt's gradle line does not record distributionSha256Sum $gradle_sum"

protoc_ver="$(sed -n 's/^VERSION="\([^"]*\)".*/\1/p' "$ROOT/scripts/install-protoc.sh" | head -1)"
protoc_sha="$(sed -n 's/^SHA256="\([^"]*\)".*/\1/p' "$ROOT/scripts/install-protoc.sh" | head -1)"
[ -n "$protoc_ver" ] && [ -n "$protoc_sha" ] || fail "scripts/install-protoc.sh carries no VERSION/SHA256 pair"
if awk '$1 == "protoc"{found=1} END{exit !found}' "$PINS"; then
  awk -v v="$protoc_ver" '$1 == "protoc"{if (index($0, v)) found=1} END{exit !found}' "$PINS" || fail "pins.txt's protoc line does not name $protoc_ver"
  awk -v s="$protoc_sha" '$1 == "protoc"{if (index($0, s)) found=1} END{exit !found}' "$PINS" || fail "pins.txt's protoc line does not record $protoc_sha"
fi

cargo_ndk="$(sed -n 's/^CARGO_NDK_VERSION="\([^"]*\)".*/\1/p' "$ROOT/scripts/build-native.sh" | head -1)"
[ -n "$cargo_ndk" ] || fail "scripts/build-native.sh carries no CARGO_NDK_VERSION"
awk -v v="$cargo_ndk" '/^cargo-ndk /{if (index($0, v)) found=1} END{exit !found}' "$PINS" || fail "pins.txt's cargo-ndk line does not name $cargo_ndk"

while IFS= read -r archive; do
  [ -n "$archive" ] || continue
  grep -qF -- "$archive" "$PINS" || fail "the builder archives $archive, which pins.txt does not name"
done < <(nocomment "$DOCKERFILE" | grep -oE '(commandlinetools|platform-tools_r|platform-[0-9]|build-tools_r|android-ndk-r)[^"[:space:]]*' | sort -u)

# Rule 6: no native-CPU flags in the build files, no --cpus in the release recipe.
NATIVE_RE='(-march=native|-mtune=native|target-cpu=native)'
BUILD_FILES=(
  "$ROOT/infra/builder/Dockerfile"
  "$ROOT/scripts/build-native.sh"
  "$ROOT/scripts/install-protoc.sh"
  "$ROOT/scripts/release/build-release.sh"
  "$ROOT/scripts/release/build-release-android.sh"
)
for f in "${BUILD_FILES[@]}"; do
  [ -f "$f" ] || continue
  hits="$(nocomment "$f" | grep -nE "$NATIVE_RE" || true)"
  [ -z "$hits" ] || while IFS= read -r line; do fail "${f#"$ROOT"/}:$line"; done <<< "$hits"
done
hits="$(nocomment "$ROOT/scripts/release/build-release.sh" | grep -nE '(^|[[:space:]])--cpus([[:space:]]|$)' || true)"
[ -z "$hits" ] || fail "scripts/release/build-release.sh names --cpus ($hits): the processor count is pinned inside the image, not by Docker"

finish builder-pins
