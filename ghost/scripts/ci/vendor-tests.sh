#!/usr/bin/env bash
# The `vendor-tests` job (Phase 9 design §15.2 item 1, §16.2; S0′'s V-12 script, moved here from
# client-core/dm-spike/scripts/v12-vendor-tests.sh by the S0′ gate slice, §22.33): vodozemac's own test
# suite at a pinned version. The crates.io package carries the unit tests in src/ (169 in 0.11.0, 152
# in 0.10.0) and its own Cargo.lock; its dev-dependencies build libolm (olm-sys, a CMake and C++
# build) and nothing of that reaches a product graph.
#
#   vendor-tests.sh <version> [work-dir]     e.g. vendor-tests.sh 0.11.0
#   vendor-tests.sh libcrux [work-dir]
#   vendor-tests.sh openmls [work-dir]     (Phase 10: OpenMLS's own suite at the pinned tag; below)
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
#
# **`vendor-tests.sh libcrux [work-dir]`: the libcrux crates' own suites (§22.35).** Every `libcrux-*`
# package the ghost lock pins (all of them are in `ghost-client-dm`'s graph) is fetched and checked
# against the lock's checksum. The packages do not carry their suites: `cargo package` drops the
# tests of `libcrux-kem` and of `libcrux-ml-kem` (its KAT files), and one of `libcrux-sha3`, and
# the tests that remain need unpublished workspace crates (`libcrux-kats`, `hacspec_sha3`). So the
# suites run in upstream's workspace at the commit `libcrux-ml-kem` was cut from
# (`.cargo_vcs_info.json`), after that workspace is made to hold exactly the published code: every
# file a package ships but its documentation is compared with upstream at that commit, and a crate
# whose upstream files differ (a later commit changed it without a version bump) gets the package's
# own files copied over it, so each suite compiles against the pinned code of every libcrux crate.
# The build is the shipped one's: toolchain 1.98.1, `LIBCRUX_DISABLE_SIMD128=1` and
# `LIBCRUX_DISABLE_SIMD256=1`, and `libcrux-portable.sh` reads what the build scripts emitted. A
# suite that fails, or that runs zero tests, fails the job; a crate classed as having no suite that
# gains a test, or a pinned libcrux crate in neither class, fails it too. The dev-dependencies of the
# workspace are resolved when the job runs (upstream commits no lock); nothing of them reaches a
# product graph.
#
#   vendor-tests.sh --suite-verdict <cargo test log> <exit code>
# prints "PASS <tests passed>" or "FAIL <reason>" for one suite: the decision the libcrux mode
# applies, alone, for scripts/gates/self-test.sh.
# Expected .crate SHA-256 (crates.io checksums, as in Cargo.lock):
#   vodozemac 0.11.0  ba935af014ca0ae5fb468daa51da81a8a0df7daad23c052c878b7c690cdf2574 (tag commit db1b34820f3102307284e762f335b3f72c735bf0)
#   vodozemac 0.10.0  b98bf83c0992966775b8012f194b07b44928996163e5a05b741b43891571ae5b (tag commit bb39ec65357989f975e0d47f9fb35e0656180151)
set -euo pipefail

# The verdict of one suite: its `cargo test` log and exit code.
suite_verdict() {
  local log="$1" code="$2" passed
  [ -r "$log" ] || { echo "FAIL no log"; return 1; }
  if grep -q '^test result: FAILED' "$log"; then echo "FAIL a test failed"; return 1; fi
  if grep -qE '^error(\[E[0-9]+\])?: ' "$log"; then echo "FAIL the suite did not build"; return 1; fi
  [ "$code" = 0 ] || { echo "FAIL exit $code"; return 1; }
  passed="$(sed -nE 's/^test result: ok\. ([0-9]+) passed.*/\1/p' "$log" | awk '{ s += $1 } END { print s + 0 }')"
  [ "$passed" -gt 0 ] || { echo "FAIL zero tests ran"; return 1; }
  echo "PASS $passed"
}

if [ "${1:-}" = "--suite-verdict" ]; then
  [ "$#" -eq 3 ] || { echo "usage: vendor-tests.sh --suite-verdict <log> <exit code>" >&2; exit 2; }
  suite_verdict "$2" "$3"
  exit $?
fi

# The crates whose own suites run, and those that have none upstream at the tested commit (a test
# appearing in one of these fails the job, so the class cannot go stale).
# libcrux-traits' `#[test]` items are generic tests inside macros that other crates instantiate
# (its `generic-tests` feature): they run in libcrux-kem's suite, and libcrux-traits runs none itself.
# libcrux-curve25519 has no `#[test]` but one doc-test, which is its suite.
LIBCRUX_SUITES=(libcrux-curve25519 libcrux-ecdh libcrux-kem libcrux-ml-kem libcrux-p256 libcrux-platform libcrux-secrets libcrux-sha2 libcrux-sha3)
LIBCRUX_NO_SUITE=(libcrux-hacl-rs libcrux-intrinsics libcrux-macros libcrux-traits)

libcrux_main() {
  local work="$1" ghost lock status=0 commit repo name version sum crate dir upstream_dir
  ghost="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  lock="$ghost/Cargo.lock"
  mkdir -p "$work"
  work="$(cd "$work" && pwd)"
  # name version checksum of every pinned libcrux package of ghost-client-dm's graph. Phase 10's slice
  # S2a added the OpenMLS provider's libcrux primitives (libcrux-aead, -aes, -chacha20poly1305,
  # -ed25519, -hkdf, -hmac, -hmac-drbg, -poly1305) to the lock; they were cut from other commits and
  # are exercised by OpenMLS's own suite with the libcrux provider (`vendor-tests.sh openmls`), so this
  # mode keeps its scope, the DM graph's crates (their own suites are deferred, faza10-forum.md §19.30).
  local dm_names
  dm_names="$(cd "$ghost" && cargo tree --locked -q -p ghost-client-dm -e normal --target all --prefix none -f '{p}' | awk '{print $1}' | sort -u)"
  [ -n "$dm_names" ] || { echo "cargo tree of ghost-client-dm printed nothing" >&2; return 1; }
  awk '/^\[\[package\]\]/ { n = v = "" } /^name = / { n = $3 } /^version = / { v = $3 }
       /^checksum = / && n ~ /^"libcrux-/ { print n, v, $3 }' "$lock" | tr -d '"' | sort > "$work/pins.all"
  awk 'NR == FNR { keep[$1] = 1; next } keep[$1]' <(printf '%s\n' "$dm_names") "$work/pins.all" > "$work/pins"
  [ -s "$work/pins" ] || { echo "no libcrux package in $lock" >&2; return 1; }
  while read -r name _ _; do
    if ! printf '%s\n' "${LIBCRUX_SUITES[@]}" "${LIBCRUX_NO_SUITE[@]}" | grep -qxF "$name"; then
      echo "$name is pinned but classed neither as a suite nor as having none" >&2; status=1
    fi
  done < "$work/pins"
  # Fetch every package through cargo (checksum-verified against the index), then against the lock.
  mkdir -p "$work/fetch/src"
  { printf '[package]\nname = "fetch"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\n'
    while read -r name version _; do printf '%s = "=%s"\n' "$name" "$version"; done < "$work/pins"; } > "$work/fetch/Cargo.toml"
  : > "$work/fetch/src/lib.rs"
  cargo fetch --manifest-path "$work/fetch/Cargo.toml" >/dev/null
  local cache="${CARGO_HOME:-$HOME/.cargo}/registry/cache"
  rm -rf "$work/pkg"; mkdir -p "$work/pkg"
  while read -r name version sum; do
    crate="$(find "$cache" -name "$name-$version.crate" | head -1)"
    [ -n "$crate" ] || { echo "$name $version: no .crate after cargo fetch" >&2; return 1; }
    echo "$sum  $crate" | sha256sum -c --quiet - || { echo "$name $version: checksum differs from the lock" >&2; return 1; }
    tar -xzf "$crate" -C "$work/pkg"
  done < "$work/pins"
  vcs() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["git"]["sha1"], d.get("path_in_vcs", ""))' "$1"; }
  version="$(awk '$1 == "libcrux-ml-kem" { print $2 }' "$work/pins")"
  read -r commit _ < <(vcs "$work/pkg/libcrux-ml-kem-$version/.cargo_vcs_info.json")
  repo="$(sed -nE 's/^repository = "(.*)"/\1/p' "$work/pkg/libcrux-ml-kem-$version/Cargo.toml")"
  [ "$repo" = "https://github.com/cryspen/libcrux" ] || { echo "unexpected repository $repo" >&2; return 1; }
  # Byte for byte, as in openmls mode: no line-ending conversion from a global core.autocrlf (on a
  # Windows host every file "differed" and the as-published count meant nothing; review of S2a, F8).
  rm -rf "$work/upstream"; git init -q "$work/upstream"; git -C "$work/upstream" config core.autocrlf false
  git -C "$work/upstream" fetch -q --depth 1 "$repo" "$commit"
  git -C "$work/upstream" checkout -q FETCH_HEAD
  echo "libcrux: suites run in $repo at $commit (the commit libcrux-ml-kem $version was cut from)"
  # A crate's directory at the tested commit, by its package name (a crate cut from another commit
  # may have moved since: libcrux-macros 0.0.3 was cut from `macros/`).
  crate_dir() {
    local found
    found="$(grep -rlxE "name = \"$1\"" --include=Cargo.toml "$work/upstream" | grep -v '/target/' || true)"
    [ "$(grep -c . <<< "$found")" = 1 ] && dirname "$found"
  }
  # Make the workspace hold the published code of every pinned crate.
  while read -r name version _; do
    dir="$work/pkg/$name-$version"
    upstream_dir="$(crate_dir "$name")"
    [ -n "$upstream_dir" ] || { echo "$name: no crate of that name at $commit" >&2; return 1; }
    local differ=0 total=0 f u
    while IFS= read -r f; do
      case "$f" in .cargo_vcs_info.json | Cargo.lock | Cargo.toml | *.md) continue ;; esac
      u="$upstream_dir/$f"; [ "$f" = Cargo.toml.orig ] && u="$upstream_dir/Cargo.toml"
      total=$((total + 1))
      cmp -s "$dir/$f" "$u" || differ=$((differ + 1))
    done < <(cd "$dir" && find . -type f | sed 's|^\./||')
    if [ "$differ" -eq 0 ]; then
      echo "  $name $version: $total files as published"
    else
      (cd "$dir" && find . -type f ! -name .cargo_vcs_info.json ! -name Cargo.lock ! -name Cargo.toml ! -name Cargo.toml.orig -exec cp --parents {} "$upstream_dir/" \;)
      cp "$dir/Cargo.toml.orig" "$upstream_dir/Cargo.toml"
      echo "  $name $version: $differ of $total files differ at $commit; the package's own files are copied over them"
    fi
  done < "$work/pins"
  cd "$work/upstream"
  # The shipped build's toolchain (upstream commits none) and its portable cfgs.
  RUSTUP_TOOLCHAIN="$(sed -nE 's/^channel = "(.*)"/\1/p' "$ghost/rust-toolchain.toml")"
  export RUSTUP_TOOLCHAIN LIBCRUX_DISABLE_SIMD128=1 LIBCRUX_DISABLE_SIMD256=1
  # Upstream commits no lock: start from the ghost lock, so every third-party crate the shipped graph
  # shares with the test graph resolves to the shipped version, and let cargo add what only the
  # workspace's other members and dev-dependencies need.
  cp "$lock" Cargo.lock
  cargo tree --workspace >/dev/null 2>&1 || { echo "cargo could not resolve the libcrux workspace" >&2; return 1; }
  : > "$work/build.json"
  local code result total_passed=0
  for name in "${LIBCRUX_SUITES[@]}"; do
    grep -q "^$name " "$work/pins" || { echo "$name: in LIBCRUX_SUITES but not pinned" >&2; status=1; continue; }
    cargo test --locked -p "$name" --no-run --message-format=json-render-diagnostics >> "$work/build.json" 2>/dev/null || true
    code=0
    cargo test --locked -p "$name" > "$work/$name.log" 2>&1 || code=$?
    result="$(suite_verdict "$work/$name.log" "$code" || true)"
    echo "  $name: $result"
    case "$result" in PASS*) total_passed=$((total_passed + ${result#PASS })) ;; *) status=1; tail -20 "$work/$name.log" >&2 ;; esac
  done
  # A crate classed as having no suite must run exactly zero tests; one that gains a test fails the
  # job until it is moved to LIBCRUX_SUITES.
  for name in "${LIBCRUX_NO_SUITE[@]}"; do
    grep -q "^$name " "$work/pins" || continue
    code=0
    cargo test --locked -p "$name" > "$work/$name.log" 2>&1 || code=$?
    result="$(suite_verdict "$work/$name.log" "$code" || true)"
    if [ "$result" = "FAIL zero tests ran" ]; then
      echo "  $name: no suite (zero tests, as classed)"
    else
      echo "  $name: classed as having no suite, but: $result" >&2; status=1
    fi
  done
  bash "$ghost/scripts/gates/libcrux-portable.sh" --json "$work/build.json" || status=1
  echo "libcrux: $total_passed tests passed over ${#LIBCRUX_SUITES[@]} suites (portable build)"
  return "$status"
}

# ---- `vendor-tests.sh openmls [work-dir]`: OpenMLS's own suite (Phase 10 design §12.2 item (1), §13.2
# `mls-vendor-tests`; S0-13, E-59; slice S2a) ------------------------------------------------------
# The crates.io package ships only benches, examples, src and tests, while OpenMLS's KATs read
# `../test_vectors/*.json`: the suite runs in a git checkout of openmls/openmls at the commit the
# package was built from (tag openmls-v0.9.0, `.cargo_vcs_info.json`), after the script has checked
# that (1) the package's SHA-256 is the checksum the ghost lock records, (2) its `.cargo_vcs_info.json`
# names OPENMLS_COMMIT, (3) the checkout is that commit, (4) every file the package ships is the
# checkout's (the published code is what runs), and (5) the three passive-client vector files the KAT
# crate commits are the checkout's (by git blob id). Then `cargo test --locked -p openmls --lib
# --features test-utils,libcrux-provider,all-ciphersuites` in the checkout (its own lock; without
# `all-ciphersuites` the parametrised tests run suite 0x0001 only, `openmls_test/src/lib.rs:8-19`), on
# the shipped toolchain with the portable libcrux cfgs, G-M9 reading the test build (libcrux-aes
# included). S0 ran it: 1 134 passed, 0 failed, 15 ignored. A failure, or fewer passes than that,
# fails the job. `test-utils` exists only here and in ghost-client-mls-kat (G-M2).
OPENMLS_COMMIT=3a3e35de3feeca8f6605143c464d5452ae584d43
OPENMLS_MIN_PASSED=1134

openmls_main() {
  local work="$1" ghost lock version sum crate dir status=0 f u differ=0 total=0
  ghost="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  lock="$ghost/Cargo.lock"
  mkdir -p "$work"
  work="$(cd "$work" && pwd)"
  read -r version sum < <(awk '/^\[\[package\]\]/ { n = v = "" } /^name = / { n = $3 } /^version = / { v = $3 }
       /^checksum = / && n == "\"openmls\"" { print v, $3 }' "$lock" | tr -d '"')
  [ -n "${version:-}" ] || { echo "openmls: not in $lock" >&2; return 1; }
  [ "$version" = 0.9.0 ] || { echo "openmls $version: OPENMLS_COMMIT names 0.9.0's commit (a bump updates it, design §3.8)" >&2; return 1; }
  mkdir -p "$work/fetch/src"
  printf '[package]\nname = "fetch"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\nopenmls = "=%s"\n' "$version" > "$work/fetch/Cargo.toml"
  : > "$work/fetch/src/lib.rs"
  cargo fetch --manifest-path "$work/fetch/Cargo.toml" >/dev/null
  crate="$(find "${CARGO_HOME:-$HOME/.cargo}/registry/cache" -name "openmls-$version.crate" | head -1)"
  [ -n "$crate" ] || { echo "openmls $version: no .crate after cargo fetch" >&2; return 1; }
  echo "$sum  $crate" | sha256sum -c --quiet - || { echo "openmls $version: checksum differs from the lock" >&2; return 1; }
  rm -rf "$work/pkg"; mkdir -p "$work/pkg"
  tar -xzf "$crate" -C "$work/pkg"
  dir="$work/pkg/openmls-$version"
  local vcs
  vcs="$(sed -nE 's/.*"sha1": *"([0-9a-f]{40})".*/\1/p' "$dir/.cargo_vcs_info.json" | head -1)"
  [ "$vcs" = "$OPENMLS_COMMIT" ] || { echo "openmls $version was built from $vcs, not $OPENMLS_COMMIT" >&2; return 1; }
  # The comparison is byte for byte: no line-ending conversion from a global core.autocrlf.
  rm -rf "$work/upstream"; git init -q "$work/upstream"; git -C "$work/upstream" config core.autocrlf false
  git -C "$work/upstream" fetch -q --depth 1 https://github.com/openmls/openmls "$OPENMLS_COMMIT"
  git -C "$work/upstream" checkout -q FETCH_HEAD
  [ "$(git -C "$work/upstream" rev-parse HEAD)" = "$OPENMLS_COMMIT" ] || { echo "the checkout is not $OPENMLS_COMMIT" >&2; return 1; }
  while IFS= read -r f; do
    case "$f" in .cargo_vcs_info.json | Cargo.lock | Cargo.toml) continue ;; esac
    u="$work/upstream/openmls/$f"; [ "$f" = Cargo.toml.orig ] && u="$work/upstream/openmls/Cargo.toml"
    # A symbolic link in the repository (openmls/README.md -> ../README.md) is published as its
    # target; git may check it out as a text file holding the target (core.symlinks=false).
    if [ "$(git -C "$work/upstream" ls-files -s -- "openmls/$f" | cut -d" " -f1)" = 120000 ]; then
      u="$work/upstream/openmls/$(dirname "$f")/$(git -C "$work/upstream" cat-file -p "HEAD:openmls/$f")"
    fi
    total=$((total + 1))
    cmp -s "$dir/$f" "$u" || { differ=$((differ + 1)); echo "  differs from the checkout: $f" >&2; }
  done < <(cd "$dir" && find . -type f | sed 's|^\./||')
  [ "$differ" = 0 ] || { echo "openmls $version: $differ of $total published files differ at $OPENMLS_COMMIT" >&2; return 1; }
  echo "openmls $version: $total published files equal the checkout at $OPENMLS_COMMIT"
  local name sha blob got
  while read -r name sha blob; do
    got="$(git -C "$work/upstream" hash-object "openmls/test_vectors/$name")"
    [ "$got" = "$blob" ] || { echo "$name: blob $got at the checkout, $blob in SOURCE.txt" >&2; status=1; }
    got="$(git hash-object "$ghost/client-core/mls-kat/vectors/$name")"
    [ "$got" = "$blob" ] || { echo "$name: the KAT crate's copy is blob $got, not $blob" >&2; status=1; }
  done < <(grep -E '^passive-client-[a-z-]+\.json ' "$ghost/client-core/mls-kat/vectors/SOURCE.txt")
  cd "$work/upstream"
  RUSTUP_TOOLCHAIN="$(sed -nE 's/^channel = "(.*)"/\1/p' "$ghost/rust-toolchain.toml")"
  export RUSTUP_TOOLCHAIN LIBCRUX_DISABLE_SIMD128=1 LIBCRUX_DISABLE_SIMD256=1
  local features="test-utils,libcrux-provider,all-ciphersuites" code=0 result passed
  cargo test --locked -p openmls --lib --features "$features" --no-run --message-format=json-render-diagnostics > "$work/build.json" 2>/dev/null || true
  cargo test --locked -p openmls --lib --features "$features" > "$work/openmls.log" 2>&1 || code=$?
  result="$(suite_verdict "$work/openmls.log" "$code" || true)"
  echo "  openmls ($features): $result; $(grep -E '^test result:' "$work/openmls.log" | tail -1)"
  case "$result" in
    PASS*)
      passed="${result#PASS }"
      [ "$passed" -ge "$OPENMLS_MIN_PASSED" ] || { echo "only $passed tests passed; S0 ran $OPENMLS_MIN_PASSED (E-59)" >&2; status=1; } ;;
    *) status=1; tail -30 "$work/openmls.log" >&2 ;;
  esac
  bash "$ghost/scripts/gates/libcrux-portable.sh" --with-aes --json "$work/build.json" || status=1
  return "$status"
}

if [ "${1:-}" = "openmls" ]; then
  openmls_main "${2:-$(mktemp -d)}"
  exit $?
fi

if [ "${1:-}" = "libcrux" ]; then
  libcrux_main "${2:-$(mktemp -d)}"
  exit $?
fi
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
