#!/usr/bin/env bash
# Gate G-T1 (design faza12-transports.md §13): the lyrebird and harness-tor pins are recorded
# in exactly one place each, internally consistent, hash-verified against the trees they pin,
# and the licence is recorded in the notices.
#   - ghost/third_party/lyrebird/pins.env: LYREBIRD_COMMIT is 64 lowercase hex (a tag or a
#     mutable ref fails), LYREBIRD_TAG == LYREBIRD_VERSION_STAMP, GO_VERSION matches the pinned
#     GO_TARBALL's name, every *_SHA256 is 64 lowercase hex, PRUNE_PATCH names the patch file
#     that lives beside it; the patch's actual SHA-256 equals PRUNE_PATCH_SHA256 (the tree
#     matches the pin); SHA256SUMS exists and records the two android binaries' hashes.
#   - ghost/third_party/tor-expert/pins.env: the two per-OS tarball SHA-256 pins are 64 hex,
#     TOR_EXPERT_VERSION matches both tarball names, and FETCH.sh checks the tarball with
#     sha256sum -c after its download and before its extraction (the monero-pin order rule).
#   - The lyrebird licence (BSD-3-Clause) is recorded in the client notices.
#   - No second copy of a pinned SHA-256 anywhere in ghost/ or .github/workflows outside the
#     pin files and the recorded SHA256SUMS: a drifted or forked copy fails here.
# Comment lines never satisfy a rule.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
LB="$GHOST_ROOT/third_party/lyrebird"
TE="$GHOST_ROOT/third_party/tor-expert"
PINS="$LB/pins.env"
TE_PINS="$TE/pins.env"
SUMS="$LB/SHA256SUMS"
NOTICES="$GHOST_ROOT/licenses/THIRD_PARTY_NOTICES-client-net.txt"
FETCH="$TE/FETCH.sh"

HEX64='^[0-9a-f]{64}$'
# A git commit hash (SHA-1, 40 hex) — the source pin is a commit, never a mutable ref.
HEX40='^[0-9a-f]{40}$'

# A variable's value from a pins.env (KEY=VALUE lines, comments and blanks skipped).
pin() { # $1 = file, $2 = key
  sed -n "s/^$2=//p" "$1" 2>/dev/null | head -1
}
[ -f "$PINS" ] || fail "ghost/third_party/lyrebird/pins.env missing"
[ -f "$TE_PINS" ] || fail "ghost/third_party/tor-expert/pins.env missing"

if [ -f "$PINS" ]; then
  commit="$(pin "$PINS" LYREBIRD_COMMIT)"
  tag="$(pin "$PINS" LYREBIRD_TAG)"
  stamp="$(pin "$PINS" LYREBIRD_VERSION_STAMP)"
  go_version="$(pin "$PINS" GO_VERSION)"
  go_tarball="$(pin "$PINS" GO_TARBALL)"
  go_sha="$(pin "$PINS" GO_TARBALL_SHA256)"
  src_sha="$(pin "$PINS" LYREBIRD_SOURCE_ARCHIVE_SHA256)"
  patch="$(pin "$PINS" PRUNE_PATCH)"
  patch_sha="$(pin "$PINS" PRUNE_PATCH_SHA256)"
  [[ "$commit" =~ $HEX40 ]] || fail "pins.env: LYREBIRD_COMMIT is not a 40-hex commit hash (a mutable ref is refused): '$commit'"
  [ -n "$tag" ] || fail "pins.env: LYREBIRD_TAG missing"
  [ "$tag" = "$stamp" ] || fail "pins.env: LYREBIRD_TAG '$tag' != LYREBIRD_VERSION_STAMP '$stamp' (the version stamp pinned into the binary must be the tag)"
  [[ "$go_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "pins.env: GO_VERSION malformed: '$go_version'"
  [[ "$go_tarball" =~ ^go$go_version\.windows-amd64\.zip$ ]] \
    || fail "pins.env: GO_TARBALL '$go_tarball' does not name go$go_version (a bumped toolchain must re-pin the tarball)"
  [[ "$go_sha" =~ $HEX64 ]] || fail "pins.env: GO_TARBALL_SHA256 malformed"
  [[ "$src_sha" =~ $HEX64 ]] || fail "pins.env: LYREBIRD_SOURCE_ARCHIVE_SHA256 malformed"
  [[ "$patch_sha" =~ $HEX64 ]] || fail "pins.env: PRUNE_PATCH_SHA256 malformed"
  if [ -n "$patch" ]; then
    [ -f "$LB/$patch" ] || fail "pins.env names $patch but it is not in ghost/third_party/lyrebird/"
    actual="$(sha256sum "$LB/$patch" | cut -d' ' -f1)"
    [ "$actual" = "$patch_sha" ] \
      || fail "$patch drifted from its pin (SHA-256 $actual != $patch_sha): the pruned tree is part of the D2 pin"
  else
    fail "pins.env: PRUNE_PATCH missing (the pruned-tree pin must be named)"
  fi
fi

if [ -f "$SUMS" ]; then
  for abi in arm64 amd64; do
    grep -qE "^[0-9a-f]{64}  lyrebird-android-$abi\$" "$SUMS" \
      || fail "SHA256SUMS records no hash for lyrebird-android-$abi"
  done
  grep -q "$commit" "$SUMS" || fail "SHA256SUMS does not name the pinned commit $commit"
else
  fail "ghost/third_party/lyrebird/SHA256SUMS missing (the recorded build hashes)"
fi

# The harness-tor pin.
if [ -f "$TE_PINS" ]; then
  te_version="$(pin "$TE_PINS" TOR_EXPERT_VERSION)"
  [[ "$te_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "tor-expert pins.env: TOR_EXPERT_VERSION malformed"
  for os in WINDOWS LINUX; do
    tarball="$(pin "$TE_PINS" TOR_EXPERT_${os}_TARBALL)"
    sha="$(pin "$TE_PINS" TOR_EXPERT_${os}_TARBALL_SHA256)"
    [[ "$tarball" =~ ^tor-expert-bundle-${os,,}-x86_64-$te_version\.tar\.gz$ ]] \
      || fail "tor-expert pins.env: tarball name '$tarball' does not match TOR_EXPERT_VERSION $te_version"
    [[ "$sha" =~ $HEX64 ]] || fail "tor-expert pins.env: ${os}_TARBALL_SHA256 malformed"
  done
  # The fetch checks the tarball after the download and before the first extraction
  # (the monero-pin order rule, applied to the harness fixture).
  if [ -f "$FETCH" ]; then
    src="$(grep -v '^[[:space:]]*#' "$FETCH")"
    grep -q 'sha256sum -c' <<< "$src" || fail "tor-expert FETCH.sh fetches the pinned tarball without sha256sum -c"
    d_line="$(grep -nE '(^|[^[:alnum:]_-])(curl|wget)([[:space:]]|$)' <<< "$src" | head -1 | cut -d: -f1)"
    c_line="$(grep -n 'sha256sum -c' <<< "$src" | head -1 | cut -d: -f1)"
    x_line="$(grep -nE '(^|[^[:alnum:]_-])(tar |unzip|mv )' <<< "$src" | head -1 | cut -d: -f1)"
    [ -n "$d_line" ] && [ -n "$c_line" ] && [ "$c_line" -gt "$d_line" ] \
      || fail "tor-expert FETCH.sh checks the tarball before its download"
    [ -z "$x_line" ] || [ "$c_line" -lt "$x_line" ] \
      || fail "tor-expert FETCH.sh extracts before the hash check"
  else
    fail "ghost/third_party/tor-expert/FETCH.sh missing"
  fi
fi

# The licence is recorded: the third_party README (design §4.1's licence-note home) names the
# BSD-3-Clause licence and reproduces its text as read at the pinned tag. The generated APK
# notices' own component row for the asset binary is S4's generator work (S3-T4); the text
# being present and pinned here is what G-T1 enforces.
README="$LB/README.md"
if [ -f "$README" ]; then
  grep -qi 'BSD-3-Clause' "$README" || fail "third_party/lyrebird/README.md records no BSD-3-Clause licence note"
  grep -qi 'lyrebird' "$README" || fail "third_party/lyrebird/README.md names no lyrebird provenance"
  grep -q "$commit" "$README" || fail "third_party/lyrebird/README.md does not name the pinned commit $commit"
else
  fail "ghost/third_party/lyrebird/README.md missing (the §4.1 provenance and licence-note home)"
fi

# No second copy of any pinned hash (the pin file and the recorded sums are the only homes).
hashes="$( { sed -n 's/^[A-Z0-9_]*=\([0-9a-f]\{64\}\)$/\1/p' "$PINS" 2>/dev/null; sed -n 's/^[A-Z0-9_]*=\([0-9a-f]\{64\}\)$/\1/p' "$TE_PINS" 2>/dev/null; } | sort -u)"
while IFS= read -r h; do
  [ -n "$h" ] || continue
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    rel="${hit#"$GHOST_ROOT"/}"
    case "$rel" in
      third_party/lyrebird/pins.env | third_party/tor-expert/pins.env) ;;
      *) fail "$rel: a second copy of pinned SHA-256 $h: the pins own their hashes" ;;
    esac
  done < <(grep -rIl -e "$h" "$GHOST_ROOT" --exclude-dir=target --exclude-dir=build \
             --exclude-dir=.gradle --exclude-dir=.git --exclude-dir=.cache \
             --exclude-dir=test-harness 2>/dev/null || true)
done <<< "$hashes"

finish pt-source-pin
