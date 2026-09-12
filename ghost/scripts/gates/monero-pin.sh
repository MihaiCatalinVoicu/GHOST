#!/usr/bin/env bash
# Gate (Phase 8 design §6.7, §13.3, §14.1; RM §9.1; ADR-26): the Monero release is pinned in one
# place, ghost/infra/issuer/monero-release.pin, and everything that fetches Monero binaries reads it.
#   - The pin file is well-formed: exactly one `version vA.B.C.D` line and one `url https://…/`
#     line, then `archive <platform> <file> <sha256> <directory>` lines: the file is
#     monero-<platform>-<version>.(tar.bz2|zip), the directory ends in -<version>, the hash is 64
#     lowercase hex digits; platforms, files and hashes are distinct; a linux-x64 archive exists
#     (the monero-regtest job downloads it). No other line.
#   - No other file of ghost/ or .github/workflows holds one of its hashes, in any letter case.
#   - A file that fetches Monero binaries (it names downloads.getmonero.org, a GitHub release
#     download of monero-project/monero, or a versioned Monero archive) names the pin and holds
#     neither a SHA-256-like value nor a versioned Monero archive name of its own: it reads both
#     from the pin. This covers the issuer Dockerfile and compose files (slice S11).
#   - .github/workflows/monero-regtest.yml exists, names the pin and checks with `sha256sum -c`.
# Skipped: build outputs and test-harness/gates (this gate's fixtures). Fixture roots mirror the
# repository: GHOST_ROOT=<root>/ghost, workflows in <root>/.github/workflows
# (test-harness/gates/monero-pin/README.md).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
PIN_REL="infra/issuer/monero-release.pin"
PIN="$GHOST_ROOT/$PIN_REL"
REPO_ROOT="$(cd "$GHOST_ROOT/.." && pwd)"
WORKFLOWS="$REPO_ROOT/.github/workflows"
JOB="$WORKFLOWS/monero-regtest.yml"
JOB_REL=".github/workflows/monero-regtest.yml"
ARCHIVE_REGEX='monero-[a-z0-9]+-[a-z0-9]+-v[0-9]+(\.[0-9]+){3}\.(tar\.bz2|zip)'
FETCH_REGEX="downloads\\.getmonero\\.org|monero-project/monero/releases/download|$ARCHIVE_REGEX"
HASH_REGEX='(^|[^0-9A-Fa-f])[0-9A-Fa-f]{64}([^0-9A-Fa-f]|$)'

# Files of ghost/ and .github/workflows matching grep's pattern ($1: -E or -F, $2: pattern), except
# the pin, build outputs and the gate fixtures; absolute paths.
scan() {
  {
    grep -rIl "$1" -i --exclude-dir=target --exclude-dir=build --exclude-dir=.gradle --exclude-dir=.git \
      -e "$2" "$GHOST_ROOT" 2>/dev/null || true
    if [ -d "$WORKFLOWS" ]; then grep -rIl "$1" -i -e "$2" "$WORKFLOWS" 2>/dev/null || true; fi
  } | grep -v -F -e "$GHOST_ROOT/test-harness/gates/" | grep -v -x -F -e "$PIN" | sort -u || true
}
rel() { printf '%s' "${1#"$REPO_ROOT"/}"; }

if [ ! -f "$PIN" ]; then
  fail "ghost/$PIN_REL: monero-release.pin missing"
  finish monero-pin
fi

version="" versions=0 urls=0 n=0
declare -A platforms=() files=() seen_hashes=()
hashes=()
while IFS= read -r line || [ -n "$line" ]; do
  n=$((n + 1))
  line="${line%$'\r'}"
  case "$line" in '' | '#'*) continue ;; esac
  read -r -a f <<< "$line"
  case "${f[0]}" in
    version)
      versions=$((versions + 1))
      if [ "${#f[@]}" -eq 2 ] && [[ "${f[1]}" =~ ^v[0-9]+(\.[0-9]+){3}$ ]]; then
        version="${f[1]}"
      else
        fail "ghost/$PIN_REL:$n: malformed version line"
      fi
      ;;
    url)
      urls=$((urls + 1))
      if [ "${#f[@]}" -ne 2 ] || ! [[ "${f[1]}" =~ ^https://[a-z0-9.-]+/([A-Za-z0-9._-]+/)*$ ]]; then
        fail "ghost/$PIN_REL:$n: malformed url line"
      fi
      ;;
    archive)
      if [ "${#f[@]}" -ne 5 ]; then fail "ghost/$PIN_REL:$n: malformed archive line"; continue; fi
      platform="${f[1]}" file="${f[2]}" sha="${f[3]}" dir="${f[4]}"
      if [ -z "$version" ]; then fail "ghost/$PIN_REL:$n: archive line before the version line"; continue; fi
      [[ "$platform" =~ ^[a-z0-9]+-[a-z0-9]+$ ]] || fail "ghost/$PIN_REL:$n: malformed platform '$platform'"
      [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || fail "ghost/$PIN_REL:$n: malformed SHA-256 for $file"
      case "$file" in
        "monero-$platform-$version.tar.bz2" | "monero-$platform-$version.zip") ;;
        *) fail "ghost/$PIN_REL:$n: archive name '$file' is not monero-$platform-$version.(tar.bz2|zip)" ;;
      esac
      if ! [[ "$dir" =~ ^monero-[A-Za-z0-9._-]+$ ]] || [ "${dir%-"$version"}" = "$dir" ]; then
        fail "ghost/$PIN_REL:$n: directory '$dir' is not monero-<triple>-$version"
      fi
      [ -z "${platforms[$platform]:-}" ] || fail "ghost/$PIN_REL:$n: platform $platform listed twice"
      [ -z "${files[$file]:-}" ] || fail "ghost/$PIN_REL:$n: archive $file listed twice"
      [ -z "${seen_hashes[$sha]:-}" ] || fail "ghost/$PIN_REL:$n: SHA-256 listed twice"
      platforms[$platform]=1 files[$file]=1 seen_hashes[$sha]=1
      hashes+=("$sha")
      ;;
    *) fail "ghost/$PIN_REL:$n: unknown line '${f[0]}'" ;;
  esac
done < "$PIN"
[ "$versions" -eq 1 ] || fail "ghost/$PIN_REL: needs exactly one version line (found $versions)"
[ "$urls" -eq 1 ] || fail "ghost/$PIN_REL: needs exactly one url line (found $urls)"
[ -n "${platforms[linux-x64]:-}" ] || fail "ghost/$PIN_REL: no linux-x64 archive (the monero-regtest job downloads it)"

# No second copy of a pinned hash.
for sha in "${hashes[@]}"; do
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || continue
  while IFS= read -r hit; do
    [ -n "$hit" ] && fail "$(rel "$hit"): second copy of a pinned SHA-256 ($sha): read it from ghost/$PIN_REL"
  done < <(scan -F "$sha")
done

# Every file that fetches Monero binaries reads the pin and pins nothing itself.
while IFS= read -r f; do
  [ -n "$f" ] || continue
  r="$(rel "$f")"
  grep -qF "monero-release.pin" "$f" || fail "$r: fetches Monero binaries without reading ghost/$PIN_REL"
  while IFS= read -r hit; do
    [ -n "$hit" ] && fail "$r:${hit%%:*}: a Monero archive name of its own: read it from ghost/$PIN_REL"
  done < <(grep -noE "$ARCHIVE_REGEX" "$f" || true)
  while IFS= read -r hit; do
    [ -n "$hit" ] && fail "$r:${hit%%:*}: a SHA-256-like value in a file that fetches Monero: read it from ghost/$PIN_REL"
  done < <(grep -nE "$HASH_REGEX" "$f" || true)
done < <(scan -E "$FETCH_REGEX")

# The regtest job reads the pin and checks the archive against it.
if [ ! -f "$JOB" ]; then
  fail "$JOB_REL: the regtest workflow is missing"
else
  grep -qF "$PIN_REL" "$JOB" || fail "$JOB_REL: does not read ghost/$PIN_REL"
  grep -qE 'sha256sum (-c|--check)' "$JOB" || fail "$JOB_REL: does not check the archive with sha256sum -c"
fi
finish monero-pin
