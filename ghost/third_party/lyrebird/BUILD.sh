#!/usr/bin/env bash
# GHOST Phase 12 — lyrebird BUILD.sh (rev 2, OA-3 applied; see
# docs/design/faza12-s0-evidence.md §10 and the design's §4).
#
# Source = lyrebird 0.9.0 @ 89d54872… + prune-snowflake.patch (pinned,
# hash-verified): the binary carries exactly the approved P0 set
# (obfs4 + webtunnel). See Q-S-T1(b) in the evidence doc.
#
# Discipline mirrored from scripts/build-native.sh: pinned sources, pinned
# toolchain, fixed work paths, two same-path builds per target with a hash
# compare, and a builder-path leak check on the outputs.
#
# Preconditions: this repo checkout; network for the two fetches (cached
# under third_party/lyrebird/toolchain/ and .cache/, both git-ignored).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"          # ghost/third_party/lyrebird
ROOT="$(cd "$HERE/../../.." && pwd)"            # repo root (ghost/)
TOOLCHAIN_DIR="$HERE/toolchain"
CACHE="$HERE/.cache"
source "$HERE/pins.env"

GO_ZIP="$CACHE/$GO_TARBALL"
SRC="$CACHE/lyrebird-$LYREBIRD_TAG"
OUT="$HERE/out"                                  # git-ignored build output

mkdir -p "$TOOLCHAIN_DIR" "$CACHE" "$OUT"

# --- 1. toolchain (Q8: never the host's ambient Go) ---
if [ ! -x "$TOOLCHAIN_DIR/go/bin/go$(uname -s | grep -qi windows && echo .exe)" ]; then
  echo "[BUILD] fetching $GO_TARBALL from go.dev"
  curl -fsSL -o "$GO_ZIP" "https://go.dev/dl/$GO_TARBALL"
  echo "$GO_TARBALL_SHA256  $GO_ZIP" | sha256sum -c -
  (cd "$TOOLCHAIN_DIR" && unzip -q -o "$GO_ZIP")
fi
export GOROOT="$TOOLCHAIN_DIR/go"
export PATH="$GOROOT/bin:$PATH"
export GOPATH="$CACHE/gopath"                    # fixed paths: no $HOME leakage
export GOMODCACHE="$CACHE/gomodcache"

# --- 2. source at the pinned commit ---
if [ ! -d "$SRC/.git" ]; then
  echo "[BUILD] cloning lyrebird at $LYREBIRD_TAG"
  git clone --quiet https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird.git "$SRC"
fi
git -C "$SRC" fetch --quiet --tags origin
git -C "$SRC" checkout --quiet "$LYREBIRD_COMMIT"
echo "[BUILD] lyrebird $(git -C "$SRC" rev-parse HEAD)"

# --- 2b. the pinned prune patch (rev 2, OA-3 applied; part of the D2 pin) ---
# Verify the patch file first, then apply it to the CLEAN pinned tree. The
# binary must carry exactly the approved P0 set (obfs4 + webtunnel): no
# snowflake, no pion/webrtc, no aws-sdk. See docs/design/faza12-s0-evidence.md §10.
PATCH="$HERE/$PRUNE_PATCH"
echo "$PRUNE_PATCH_SHA256  $PATCH" | sha256sum -c -
# reset any previous patch application so re-runs are idempotent
git -C "$SRC" reset --quiet --hard "$LYREBIRD_COMMIT"
if ! git -C "$SRC" apply --check "$PATCH" 2>/dev/null; then
  echo "[BUILD] FAIL: $PRUNE_PATCH does not apply to $LYREBIRD_COMMIT" >&2; exit 1
fi
git -C "$SRC" apply "$PATCH"
echo "[BUILD] applied $PRUNE_PATCH ($(git -C "$SRC" diff --shortstat | tail -1))"

# --- 3. build flags (S0-T2 of the evidence doc) ---
export GOFLAGS='-trimpath -mod=readonly -buildvcs=false'
export LDFLAGS="-s -w $GO_EXTRA_LDFLAGS -X main.lyrebirdVersion=$LYREBIRD_VERSION_STAMP"
NDK_CC="$ANDROID_NDK_ROOT/$NDK_VERSION/$NDK_CLANG_ABI29_X86_64"

# --- 3b. pruned-graph assertion: the module graph must not contain the
# transports the patch removed (they are the size blow-up OA-3 fired on).
if (cd "$SRC" && go list -m all 2>/dev/null | grep -qiE 'snowflake|pion/|aws-sdk'); then
  echo "[BUILD] FAIL: pruned dependency still in the module graph" >&2; exit 1
fi
echo "[BUILD] module graph pruned (no snowflake/pion/aws-sdk)"

build_one() { # goos goarch cgo out-name [cc]
  local goos=$1 goarch=$2 cgo=$3 name=$4 cc=${5:-}
  echo "[BUILD] $name ($goos/$goarch, CGO_ENABLED=$cgo)"
  if [ -n "$cc" ]; then
    CGO_ENABLED=$cgo GOOS=$goos GOARCH=$goarch CC="$cc" \
      go build -ldflags "$LDFLAGS" -o "$OUT/$name" ./cmd/lyrebird
  else
    CGO_ENABLED=$cgo GOOS=$goos GOARCH=$goarch \
      go build -ldflags "$LDFLAGS" -o "$OUT/$name" ./cmd/lyrebird
  fi
}

double_build() { # same path built twice, hashes must match (the G-T2/G-T1 rule)
  local goos=$1 goarch=$2 cgo=$3 name=$4 cc=${5:-}
  (cd "$SRC" && build_one "$goos" "$goarch" "$cgo" "$name" "$cc")
  local h1; h1=$(sha256sum "$OUT/$name" | cut -d' ' -f1)
  rm -f "$OUT/$name"
  (cd "$SRC" && build_one "$goos" "$goarch" "$cgo" "$name" "$cc")
  local h2; h2=$(sha256sum "$OUT/$name" | cut -d' ' -f1)
  if [ "$h1" != "$h2" ]; then
    echo "[BUILD] FAIL: $name not reproducible ($h1 != $h2)" >&2; exit 1
  fi
  echo "$h2  $name" >> "$OUT/SHA256SUMS.new"
}

: > "$OUT/SHA256SUMS.new"
# S0-T2(b): android/amd64 hard-requires external (cgo) linking in cmd/go.
double_build android arm64 0 lyrebird-android-arm64
double_build android amd64 1 lyrebird-android-amd64 "$NDK_CC"
mv "$OUT/SHA256SUMS.new" "$OUT/SHA256SUMS"

# --- 4. leak check (build-native.sh's spellings idea) ---
echo "[BUILD] leak check"
if grep -aoE "${USER:-nobody}|$(pwd -P | sed 's/[].[^$*\/]/\\&/g')|$HOME" "$OUT"/lyrebird-android-* | head -5; then
  echo "[BUILD] FAIL: builder path leaked into a binary" >&2; exit 1
fi

echo "[BUILD] done. Compare $OUT/SHA256SUMS against the recorded SHA256SUMS (G-T4's twin)."
