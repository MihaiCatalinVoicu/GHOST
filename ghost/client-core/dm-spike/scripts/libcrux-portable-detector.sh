#!/usr/bin/env bash
# V-6 / G-R3 prototype: the portable-only detector for libcrux (design §2.3, Q55).
#
# Runs `cargo build --message-format=json <args>` and reads cargo's `build-script-executed`
# messages, which cargo emits for every build script of the build, fresh or re-run, with the
# `cargo:rustc-cfg` values the compiler receives. Fails if a libcrux-ml-kem, libcrux-sha3 or
# libcrux-intrinsics build script emitted `feature="simd128"` or `feature="simd256"`, and if the
# build contains none of them (a detector that sees nothing proves nothing).
# Usage: libcrux-portable-detector.sh <cargo build arguments>
set -euo pipefail
out="$(cargo build --message-format=json "$@")"
lines="$(printf '%s\n' "$out" | grep '"reason":"build-script-executed"' | grep -E '#libcrux-(ml-kem|sha3|intrinsics)@' || true)"
if [ -z "$lines" ]; then
  echo "detector: no libcrux-ml-kem, libcrux-sha3 or libcrux-intrinsics build script in this build" >&2
  exit 2
fi
count="$(printf '%s\n' "$lines" | wc -l | tr -d ' ')"
if printf '%s\n' "$lines" | grep -Eq 'simd(128|256)'; then
  printf '%s\n' "$lines" | grep -Eo '#libcrux-[a-z0-9-]+@[0-9.]+|"cfgs":\[[^]]*\]' >&2
  echo "detector: FAIL, a libcrux build script enabled SIMD code ($count scripts)" >&2
  exit 1
fi
echo "detector: portable only ($count libcrux build scripts, no simd cfg)"
