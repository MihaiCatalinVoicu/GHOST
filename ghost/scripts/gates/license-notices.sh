#!/usr/bin/env bash
# Gate G-L1 (ADR-37; Phase 9 design §2.10.2, §22.8.10 point 3), and G-L2 in its android mode: the
# committed third-party notices equal the notices regenerated from what ships.
#   license-notices.sh rust [--write]
#       ghost/licenses/THIRD_PARTY_NOTICES-<graph>.txt for every shipped Rust graph of
#       ghost/licenses/graphs.txt (libghost_client_net.so, the relay, the issuer), from Cargo.lock and
#       the published sources (CI job rust).
#   license-notices.sh android <components> [--write]
#       ghost/licenses/THIRD_PARTY_NOTICES-android.txt from the release runtime components listed by
#       `./gradlew :app:releaseRuntimeComponents` (app/build/licenses/release-runtime-components.txt),
#       their classes jars and the artifacts as published (the AAR or jar next to the POM), their POMs
#       in the Gradle cache and scripts/gates/gradle-license-allowlist.txt (G-L2; CI job android,
#       after the build).
# Fails on a difference, on a component used under no licence whose text it can resolve (from the
# component, the upstream snapshot ghost/licenses/upstream or the SPDX texts ghost/licenses/spdx),
# on an SPDX text that does not match the SHA-256 ghost/licenses/spdx/SOURCE.txt records for it, on
# a NOTICE of the upstream snapshot that is missing, on an undecided licence file of vendored
# sources (ghost/licenses/vendored-licences.txt) and, in android mode, on an unknown or copyleft
# licence. --write rewrites the committed files instead of comparing (review the diff). The APK
# asset assets/THIRD_PARTY_NOTICES.txt is apk-notices-preamble.txt, then the android part, then the
# client-net part (app/build.gradle.kts; checked in the APK by apk-notices.sh, G-L3).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
LIC="$GHOST_ROOT/licenses"
mode="${1:-}"
[ "$mode" = rust ] || [ "$mode" = android ] || { echo "usage: license-notices.sh rust [--write] | android <components> [--write]" >&2; exit 2; }
shift
components=""
if [ "$mode" = android ]; then
  components="${1:-}"
  [ -n "$components" ] && [ -f "$components" ] || { echo "license-notices.sh android: components file '$components' not found (./gradlew :app:releaseRuntimeComponents)" >&2; exit 2; }
  shift
fi
write=0
[ "${1:-}" = --write ] && write=1
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

compare() { # $1 = part name
  local committed="$LIC/THIRD_PARTY_NOTICES-$1.txt" fresh="$work/THIRD_PARTY_NOTICES-$1.txt"
  if [ "$write" = 1 ]; then
    cp "$fresh" "$committed"
    echo "wrote licenses/THIRD_PARTY_NOTICES-$1.txt" >&2
  elif [ ! -f "$committed" ]; then
    fail "licenses/THIRD_PARTY_NOTICES-$1.txt is missing (license-notices.sh $mode ${components:+<components> }--write, then review)"
  elif ! cmp -s "$committed" "$fresh"; then
    diff -u "$committed" "$fresh" | head -40 >&2 || true
    fail "licenses/THIRD_PARTY_NOTICES-$1.txt differs from the regenerated notices (license-notices.sh $mode ${components:+<components> }--write, then review)"
  fi
}
generate() { # $1 = perl command, rest = arguments; turns its GATE-FAIL lines into failures
  local out rc=0
  out="$(GHOST_ROOT="$GHOST_ROOT" perl "$GATES_DIR/licenses.pl" "$@" 2>"$work/stderr")" || rc=$?
  while IFS= read -r line; do
    [ -n "$line" ] && fail "${line#GATE-FAIL: }"
  done <<< "$out"
  if [ "$rc" -gt 1 ]; then cat "$work/stderr" >&2; fail "licenses.pl $1 stopped (exit $rc)"; fi
  [ "$rc" = 0 ]
}

if [ "$mode" = rust ]; then
  command -v cargo >/dev/null || [ -n "${GHOST_LICENSE_PACKAGES:-}" ] || { echo "cargo not found" >&2; exit 2; }
  if [ -z "${GHOST_LICENSE_PACKAGES:-}" ]; then
    (cd "$GHOST_ROOT" && cargo fetch --locked >/dev/null) || fail "cargo fetch --locked"
  fi
  graphs="$(awk '$1 == "graph" {print $2}' "$LIC/graphs.txt")"
  [ -n "$graphs" ] || fail "licenses/graphs.txt names no graph"
  for g in $graphs; do
    generate rust-notices "$g" "$work/THIRD_PARTY_NOTICES-$g.txt" && compare "$g"
  done
  # A notices file of a graph that is no longer shipped.
  for f in "$LIC"/THIRD_PARTY_NOTICES-*.txt; do
    [ -f "$f" ] || continue
    name="$(basename "$f" .txt)"
    name="${name#THIRD_PARTY_NOTICES-}"
    [ "$name" = android ] && continue
    grep -qx -- "$name" <<< "$graphs" || fail "licenses/THIRD_PARTY_NOTICES-$name.txt names no graph of licenses/graphs.txt"
  done
else
  generate android-notices "$components" "$work/THIRD_PARTY_NOTICES-android.txt" && compare android
fi
finish "license-notices ($mode)"
