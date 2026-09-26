#!/usr/bin/env bash
# The `vendor-tests` job (Phase 9 design §15.2 item 1, §16.2; S0′'s V-12 script, moved here from
# client-core/dm-spike/scripts/v12-vendor-tests.sh by the S0′ gate slice, §22.33): vodozemac's own test
# suite at a pinned version. The crates.io package carries the unit tests in src/ (169 in 0.11.0, 152
# in 0.10.0) and its own Cargo.lock; its dev-dependencies build libolm (olm-sys, a CMake and C++
# build) and nothing of that reaches a product graph.
#
#   vendor-tests.sh <version> [work-dir]     e.g. vendor-tests.sh 0.11.0
#
# Checks the .crate against the checksum the ghost lock pins, extracts it, and runs `cargo test`
# twice: default features, then --all-features. Needs network (the dev-dependencies are not in the
# product lock), cmake, a C++ compiler and the pinned toolchain.
#
# **Upstream's dev-dependency patch (first run, S0′ gate slice, §22.33).** The package's own tests do
# not compile against its packaged lock: vodozemac's workspace overrides olm-rs with
# `[patch.crates-io] olm-rs = { git = "https://github.com/poljar/olm-rs", rev = "…" }`, which
# `cargo package` keeps only in `Cargo.toml.orig`, so the packaged lock resolves olm-rs 2.2.0 from
# crates.io, which lacks `OlmSas::calculate_mac_fixed_base64` (E0599 in src/sas.rs). The script
# therefore re-applies the `[patch.crates-io]` section of the verified package's own
# `Cargo.toml.orig` (a git revision, a pinned commit), lets cargo move only what the patch moves, and
# fails if the lock changed for any package that is neither named by the patch nor now taken from a
# git source pinned by `rev=` (the patched olm-rs brings its olm-sys from git at a pinned revision):
# no crates.io package may move, every other package stays at the version the package's lock records.
#
# **The fuzz-corpus tests.** Five unit tests (`fuzz_corpus_*`) read `afl/<target>/in/`, corpora the
# repository has and `cargo package` does not ship (the package holds `afl/README.md` only), so they
# cannot pass on the package and are skipped by name; the others must all pass. The count is printed
# and checked: 164 of 0.11.0's 169 run in each of the two runs.
# Expected .crate SHA-256 (crates.io checksums, as in Cargo.lock):
#   vodozemac 0.11.0  ba935af014ca0ae5fb468daa51da81a8a0df7daad23c052c878b7c690cdf2574 (tag commit db1b34820f3102307284e762f335b3f72c735bf0)
#   vodozemac 0.10.0  b98bf83c0992966775b8012f194b07b44928996163e5a05b741b43891571ae5b (tag commit bb39ec65357989f975e0d47f9fb35e0656180151)
set -euo pipefail
VERSION="${1:?usage: vendor-tests.sh <version> [work-dir]}"
WORK="${2:-$(mktemp -d)}"
mkdir -p "$WORK"
case "$VERSION" in
  0.11.0) SUM=ba935af014ca0ae5fb468daa51da81a8a0df7daad23c052c878b7c690cdf2574 ;;
  0.10.0) SUM=b98bf83c0992966775b8012f194b07b44928996163e5a05b741b43891571ae5b ;;
  *) echo "unpinned version $VERSION" >&2; exit 2 ;;
esac
command -v cmake >/dev/null || { echo "cmake is required (olm-sys builds libolm)" >&2; exit 2; }
CACHE="${CARGO_HOME:-$HOME/.cargo}/registry/cache"
CRATE="$(find "$CACHE" -name "vodozemac-$VERSION.crate" 2>/dev/null | head -1)"
if [ -z "$CRATE" ]; then
  # Fetch through cargo (checksum-verified against the index) with a throwaway manifest.
  mkdir -p "$WORK/fetch/src"
  printf '[package]\nname = "fetch"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\nvodozemac = "=%s"\n' "$VERSION" > "$WORK/fetch/Cargo.toml"
  : > "$WORK/fetch/src/lib.rs"
  cargo fetch --manifest-path "$WORK/fetch/Cargo.toml"
  CRATE="$(find "$CACHE" -name "vodozemac-$VERSION.crate" | head -1)"
fi
echo "$SUM  $CRATE" | sha256sum -c -
rm -rf "$WORK/vodozemac-$VERSION"
tar -xzf "$CRATE" -C "$WORK"
cd "$WORK/vodozemac-$VERSION"

# `name version source` of every package of a lock file.
lock_packages() {
  awk '/^\[\[package\]\]/ { if (n != "") print n, v, s; n = v = s = ""; next }
       /^name = / { n = $3 } /^version = / { v = $3 } /^source = / { s = $3 }
       END { if (n != "") print n, v, s }' "$1" | tr -d '"' | sort
}
patched=""
if grep -q '^\[patch\.crates-io\]' Cargo.toml.orig; then
  section="$(awk '/^\[patch\.crates-io\]/ { p = 1; print; next } /^\[/ { p = 0 } p' Cargo.toml.orig)"
  patched="$(sed -n '2,$ s/^\([A-Za-z0-9_-]*\)[[:space:]]*=.*/\1/p' <<< "$section" | sort -u)"
  echo "re-applying upstream's [patch.crates-io] from Cargo.toml.orig for: $(tr '\n' ' ' <<< "$patched")"
  printf '\n%s\n' "$section" >> Cargo.toml
fi
cp Cargo.lock "$WORK/Cargo.lock.package"
status=0
SKIP=(--skip fuzz_corpus_)
cargo test -- "${SKIP[@]}" 2>&1 | tee "$WORK/default.log" | grep -E '^test result|FAILED|panicked|^error' || true
cargo test --all-features -- "${SKIP[@]}" 2>&1 | tee "$WORK/all-features.log" | grep -E '^test result|FAILED|panicked|^error' || true
# The lock may differ from the packaged one only in the packages the patch names and in packages now
# taken from a git source pinned by revision; a crates.io package that moved fails.
while read -r name version source; do
  [ -n "$name" ] || continue
  grep -qxF "$name" <<< "$patched" && continue
  case "$source" in git+*\?rev=*) continue ;; esac
  echo "the lock changed for $name $version (${source:-no source}), which upstream's patch does not account for" >&2; status=1
done < <(comm -13 <(lock_packages "$WORK/Cargo.lock.package") <(lock_packages Cargo.lock))
# `grep -c` exits 1 when it counts nothing, which `set -e` would take for a failure of the script.
skipped="$({ grep -hcE '^test .*fuzz_corpus_' "$WORK/default.log" "$WORK/all-features.log" || true; } | awk '{ s += $1 } END { print s + 0 }')"
[ "$skipped" = 0 ] || { echo "a fuzz_corpus_ test ran although it was skipped ($skipped)" >&2; status=1; }
for log in "$WORK/default.log" "$WORK/all-features.log"; do
  if grep -q 'test result: FAILED' "$log" || ! grep -q '^test result: ok' "$log"; then
    echo "$(basename "$log" .log): vodozemac $VERSION's own tests did not all pass" >&2; status=1
  fi
done
passed="$(cat "$WORK/default.log" "$WORK/all-features.log" | sed -nE 's/^test result: ok\. ([0-9]+) passed.*/\1/p' | awk '{ s += $1 } END { print s + 0 }')"
lib="$(sed -nE 's/^test result: ok\. ([0-9]+) passed; 0 failed; 0 ignored; 0 measured; 5 filtered out.*/\1/p' "$WORK/default.log" "$WORK/all-features.log" | tr '\n' ' ')"
echo "vodozemac $VERSION: ${passed:-0} tests passed over both runs (the library's unit tests: ${lib:-none} with the five fuzz_corpus_ tests filtered out)"
exit "$status"
