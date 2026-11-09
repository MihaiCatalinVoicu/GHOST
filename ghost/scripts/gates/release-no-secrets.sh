#!/usr/bin/env bash
# Gate G-D1 (Phase 14 design faza14-distribution.md §12.1; D25's signing material stays out of
# the tree; the carve-outs are the row's own): no signing material is committed.
#   (a) No private-key material anywhere outside the listed test fixtures
#       (protocol/test-vectors/apk/, test-harness/update/keys/): PEM/OpenSSH/PKCS#8 private-key
#       headers by text, Java keystores (.jks/.keystore) and PKCS#12 (.p12/.pfx) by extension
#       AND by magic (JKS's FE ED FE ED; PKCS#12's DER SEQUENCE 30 82 on a file carrying no
#       keystore extension — a renamed keystore), onion service secret keys by name and by C
#       Tor's secret-key header — extending entitlement-schedule.sh's search to infra/mirror
#       (design §7.1's own sentence). Build outputs (target/, build/) are skipped, like the
#       other tree gates.
#   (b) app/build.gradle.kts signs only with the debug key, and only where the row allows:
#       the release build type must carry no signingConfig at all (it signs offline, RK1);
#       every signingConfig assignment names signingConfigs.getByName("debug").
#   (c) scripts/ invokes none of apksigner, jarsigner, bundletool, ykman, yubico-piv-tool or
#       sigsum-submit (comment-stripped; the manual's mentions do not count).
# Documented as manual (no .github/workflows in this checkout): the same scan over the CI
# workflow YAML when it lands.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
ROOT="${GHOST_D1_ROOT:-$GHOST_ROOT}"
REAL_ROOT="$(cd "$GATES_DIR/../.." && pwd -P)"
if [ -n "${GHOST_D1_ROOT:-}" ] && [ "$(cd "$ROOT" && pwd -P)" = "$REAL_ROOT" ]; then
  echo "GHOST_D1_ROOT is a self-test hook for fixture roots only" >&2
  exit 2
fi
[ -f "$ROOT/android/app/build.gradle.kts" ] || { echo "G-D1: $ROOT/android/app/build.gradle.kts missing" >&2; exit 2; }

CARVE_OUTS="protocol/test-vectors/apk/ test-harness/update/keys/"
skips() { # the carve-outs and build outputs, one -path expression per line
  printf '%s\n' "$ROOT/protocol/test-vectors/apk" "$ROOT/test-harness/update/keys"
  # House precedent (entitlement-schedule.sh's skipped_trees): the gate fixtures under
  # test-harness/gates are each other's canaries; they self-test and are not production.
  # .git is not the tree.
  printf '%s\n' "$ROOT/test-harness/gates" "$ROOT/.git"
  printf '%s\n' "$ROOT/android/update/build" "$ROOT/android/network/build"
  # third_party/lyrebird's toolchain is upstream's own: the vendored Go toolchain's crypto testdata
  # and module cache carry upstream TEST keys (Go stdlib nist-pkits certs, x/crypto ssh test keys) —
  # signing material of the Go project, never of GHOST. Lyrebird's own integrity is pinned by
  # pt-source-pin (G-T1); the gate looks for GHOST's signing material.
  printf '%s\n' "$ROOT/third_party/lyrebird/toolchain" "$ROOT/third_party/lyrebird/.cache"
  find "$ROOT" -type d \( -name target -o -name build -o -name .gradle \) -not -path '*/src/*' 2>/dev/null | head -200
}

# (a) private-key text headers, keystore extensions and magics, onion secret keys. Text
# checks are batched (one grep over the tree); magic checks run only on files that cannot be
# text, so a source tree of thousands of .rs/.kt files costs two processes total.
ONION_HDR_HEX='3d3d206564323535313976312d7365637265743a207479706530203d3d000000'
TEXT_EXT='rs|kt|java|md|txt|toml|kts|sh|yml|yaml|json|xml|gradle|properties|proto|cmake|lock|css|html|cfg|ini|conf|gitignore|gitattributes|bat|cmd|pl|py|csv|diff|patch|svg|adoc'
prune=()
while IFS= read -r d; do prune+=(-path "$d" -prune -o); done < <(skips)
file_list="$(find "$ROOT" \( "${prune[@]}" -type f -print \) 2>/dev/null | sort)"

# Name and extension checks in one awk pass (the tree can hold tens of thousands of
# files; a bash loop over them is minutes on slow filesystems). Binary candidates go to
# a temp list for the magic checks.
# Which files are binary? grep's -I answers in one C pass over the tree; only true
# binaries reach the per-file od loop.
candidates="$(mktemp)"
printf '%s
' "$file_list" | xargs grep -Il '' 2>/dev/null | sort > "$candidates.text" || true
comm -23 <(printf '%s
' "$file_list" | sort) "$candidates.text" > "$candidates"
rm -f "$candidates.text"

while IFS= read -r f; do
  [ -n "$f" ] || continue
  rel="${f#"$ROOT"/}"
  head32="$(od -A n -t x1 -N 32 "$f" 2>/dev/null | tr -d ' 
')"
  magic4="${head32:0:8}"
  [ "$magic4" != "feedfeed" ] || fail "$rel: a JKS keystore by magic"
  # A file starting with a DER SEQUENCE that carries no keystore extension is a possible
  # renamed PKCS#12 (the honest, narrow magic check).
  [ "${magic4:0:4}" != "3082" ] || fail "$rel: starts with a DER SEQUENCE - a possible renamed PKCS#12 keystore"
  [ "$head32" != "$ONION_HDR_HEX" ] || fail "$rel: a Tor onion service secret key by C Tor's header"
done < <(grep -E '^/' "$candidates" 2>/dev/null || true)
rm -f "$candidates"

key_hits="$(printf '%s
' "$file_list" | grep -vE '/(protocol/test-vectors/apk|test-harness/update/keys)/' | xargs grep -alE -- '-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----' 2>/dev/null || true)"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  fail "${f#"$ROOT"/}: a PEM/OpenSSH/PKCS#8 private-key header"
done <<< "$key_hits"

# (b) the APK signs with the debug key only where the row allows: never in `release`.
gradle="$ROOT/android/app/build.gradle.kts"
while IFS= read -r line; do
  n="$(printf '%s' "$line" | cut -d: -f1)"
  rest="${line#*:}"
  grep -q 'signingConfigs.getByName("debug")' <<< "$rest" \
    || fail "app/build.gradle.kts:$n: a signingConfig that is not the debug key: $(printf '%.60s' "$rest")"
done < <(grep -n 'signingConfig *=' "$gradle" || true)
release_block="$(awk '/^[[:space:]]*release[[:space:]]*\{/ {d=1} d {print; o=gsub(/\{/,"{"); c=gsub(/\}/,"}"); depth+=o-c; if (depth==0) exit}' "$gradle")"
# Inside `release` the row's only allowance is the smoke build's conditional debug key
# (the gate build type is a sibling, checked by the every-assignment rule above).
while IFS= read -r line; do
  n="$(printf '%s' "$line" | cut -d: -f1)"
  rest="${line#*:}"
  if ! grep -q 'smokeRelease' <<< "$rest" || ! grep -q 'signingConfigs.getByName("debug")' <<< "$rest"; then
    fail "app/build.gradle.kts:$n: the release build type carries a signingConfig the row does not allow: $(printf '%.60s' "$rest")"
  fi
done < <(grep -n 'signingConfig' <<< "$release_block" || true)

# (c) no signer tooling in scripts/ (the workflow half is manual until CI lands).
while IFS= read -r f; do
  [ -n "$f" ] || continue
  hits="$(grep -vE '^[[:space:]]*#' "$f" | grep -nE '(^|[;&|[:space:]])(apksigner|jarsigner|bundletool|ykman|yubico-piv-tool|sigsum-submit)([[:space:]]|$)' || true)"
  [ -z "$hits" ] || while IFS= read -r line; do fail "${f#"$ROOT"/}:$line"; done <<< "$hits"
done < <(find "$ROOT/scripts" "$ROOT/infra" -type f \( -name '*.sh' -o -name 'Dockerfile' -o -name '*.kts' \) -print 2>/dev/null | sort)

finish release-no-secrets
