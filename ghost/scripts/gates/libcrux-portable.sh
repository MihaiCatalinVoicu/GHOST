#!/usr/bin/env bash
# Gate G-R3 (Phase 9 design §16.1 G-R3 as replaced by S0′, evidence V-6 §6.3; ADR-36, Q55; S0′ gate
# slice, §22.33): **every client build links the portable libcrux only** — the ML-KEM and SHA-3 code
# the hax/F* proofs target. The SIMD code paths of `libcrux-ml-kem`, `libcrux-sha3` and
# `libcrux-intrinsics` have no proofs (RUSTSEC-2025-0133 was an unverified aarch64 fallback), and
# their build scripts turn them on for every aarch64 (`simd128`) and x86_64 (`simd256`) build unless
# `LIBCRUX_DISABLE_SIMD128`/`LIBCRUX_DISABLE_SIMD256` are set.
#
# Why the gate reads the build and not the variables. `.cargo/config.toml` sets both variables, but
# the four build scripts read them without `cargo:rerun-if-env-changed`, so a target directory built
# once without them keeps its SIMD cfgs after they are set (S0′ measured FAIL -> FAIL -> portable ->
# portable). Every client build is therefore preceded by
#   cargo clean -p libcrux-ml-kem -p libcrux-sha3 -p libcrux-intrinsics -p libcrux-aes [--target <triple>] --release
# (build-native.sh does it for both Android triples; the CI jobs that build `ghost-dm-host` do it for
# the host), and this gate then reads what the build scripts actually emitted:
#
#   --json <file>        a `cargo build --message-format=json…` stream (a host build): every
#                        `build-script-executed` message of the four packages — cargo emits one for
#                        each build script of the build, fresh or re-run, with the cfgs rustc gets;
#   --target-dir <dir>   a profile directory (`target/<triple>/release`) after a cargo-ndk build, which
#                        prints no cargo messages: the `build/<package>-<hash>/output` file of each of
#                        the four packages. After the clean each package has **exactly one**; two or
#                        more mean a stale run the clean did not remove, and which one the build used
#                        cannot be told from the files, so the gate fails rather than guess.
#
# It fails if any `cargo:rustc-cfg` (or `cargo::rustc-cfg`) line of the four packages carries
# `feature="simd128"` or `feature="simd256"`, and if any of the three DM-graph packages (and, with
# `--with-aes`, `libcrux-aes`) is missing from a source — a
# check that sees no libcrux build proves nothing. Several `--json`/`--target-dir` arguments may be
# given; each is checked on its own.
#
# **G-M9 (Phase 10 design §13.1, §19.23; S0-8, V10-7; slice S2a): `libcrux-aes` joins the rule.**
# The OpenMLS provider's `libcrux-aead` 0.0.9 compiles `libcrux-aes` 0.0.9 (its default
# `aesgcm128`/`aesgcm256` features), whose `build.rs` emits `feature="simd128"` on aarch64 and
# `feature="simd256"` on x86_64 unless `LIBCRUX_DISABLE_SIMD128/256` are set, with no
# `rerun-if-env-changed` — the same stale-cfg hazard (V10-7: simd256 -> still simd256 after the
# variables changed -> portable after a clean). Every clean list therefore names it too
# (`cargo clean -p libcrux-ml-kem -p libcrux-sha3 -p libcrux-intrinsics -p libcrux-aes`), and this
# gate checks it in every build that has it. It is required only with `--with-aes`: until slice S2b
# links `ghost-client-mls` into `ghost-client-net` and `ghost-dm-host`, the DM builds do not compile
# it, and a build that must (the workspace test build, the OpenMLS suite) says so, so that a check
# that sees no `libcrux-aes` build there fails instead of passing vacuously.
#
# Usage: libcrux-portable.sh [--with-aes] (--json <file> | --target-dir <dir>)...
# Self-test: scripts/gates/self-test.sh runs it over test-harness/gates/libcrux-portable/.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
PACKAGES=(libcrux-ml-kem libcrux-sha3 libcrux-intrinsics libcrux-aes)
# libcrux-aes is checked wherever it was built and required only with --with-aes (G-M9).
OPTIONAL=libcrux-aes
SIMD='feature="simd(128|256)"'
[ "$#" -gt 0 ] || { echo "usage: libcrux-portable.sh [--with-aes] (--json <file> | --target-dir <dir>)..." >&2; exit 2; }
require_aes=0
args=()
for a in "$@"; do
  if [ "$a" = --with-aes ]; then require_aes=1; else args+=("$a"); fi
done
set -- "${args[@]}"
[ "$#" -gt 0 ] || { echo "usage: libcrux-portable.sh [--with-aes] (--json <file> | --target-dir <dir>)..." >&2; exit 2; }
required() { [ "$1" != "$OPTIONAL" ] || [ "$require_aes" = 1 ]; }

checked=0
while [ "$#" -gt 0 ]; do
  mode="$1"
  src="${2:-}"
  [ -n "$src" ] || { echo "usage: $mode needs an argument" >&2; exit 2; }
  shift 2
  case "$mode" in
    --json)
      [ -f "$src" ] || { fail "$src: no such build output"; continue; }
      for pkg in "${PACKAGES[@]}"; do
        # The package id is `registry+…#libcrux-ml-kem@0.0.10` (cargo 1.77+), or, for a workspace
        # path package whose directory bears its name, `path+file:///…/libcrux-ml-kem#0.0.10`
        # (upstream's layout, which vendor-tests.sh builds for the libcrux suites, §22.35); the name
        # is matched exactly, so libcrux-ml-kem never matches a longer name.
        lines="$(grep -F '"reason":"build-script-executed"' "$src" | grep -E "(#$pkg@|/$pkg#)[0-9]" || true)"
        if [ -z "$lines" ]; then
          required "$pkg" && fail "$src: no build-script-executed message of $pkg (the check would pass vacuously)"
          continue
        fi
        while IFS= read -r msg; do
          cfgs="$(grep -oE '"cfgs":\[[^]]*\]' <<< "$msg" || true)"
          if grep -qE "$SIMD" <<< "${cfgs//\\\"/\"}"; then
            fail "$src: $pkg enabled SIMD code: $cfgs (G-R3, G-M9: portable libcrux only; clean the libcrux packages and build again)"
          fi
        done <<< "$lines"
      done
      checked=$((checked + 1))
      ;;
    --target-dir)
      [ -d "$src" ] || { fail "$src: no such target directory"; continue; }
      for pkg in "${PACKAGES[@]}"; do
        mapfile -t outputs < <(find "$src/build" -mindepth 2 -maxdepth 2 -type f -name output -path "*/build/$pkg-*/output" 2>/dev/null | sort)
        # `libcrux-ml-kem-<hash>` must not be confused with a longer package name sharing the prefix.
        kept=()
        for o in "${outputs[@]}"; do
          d="$(basename "$(dirname "$o")")"
          [[ "$d" =~ ^$pkg-[0-9a-f]{16}$ ]] && kept+=("$o")
        done
        case "${#kept[@]}" in
          0) required "$pkg" && fail "$src: no build script output of $pkg (the check would pass vacuously)"; continue ;;
          1) ;;
          *) fail "$src: ${#kept[@]} build script outputs of $pkg (a stale run the libcrux clean did not remove: ${kept[*]#"$src"/})"; continue ;;
        esac
        hits="$(grep -nE "^cargo::?rustc-cfg=.*$SIMD" "${kept[0]}" || true)"
        [ -z "$hits" ] || while IFS= read -r line; do
          fail "${kept[0]}:$line (G-R3, G-M9: $pkg enabled SIMD code; clean the libcrux packages and build again)"
        done <<< "$hits"
      done
      checked=$((checked + 1))
      ;;
    *) echo "unknown argument $mode (usage: libcrux-portable.sh [--with-aes] (--json <file> | --target-dir <dir>)...)" >&2; exit 2 ;;
  esac
done
[ "$checked" -gt 0 ] || fail "no build was checked"
finish libcrux-portable
