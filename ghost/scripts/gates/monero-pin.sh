#!/usr/bin/env bash
# Gate (Phase 8 design §6.7, §13.3, §13.6, §14.1; RM §9.1; ADR-26): the Monero release is pinned in
# one place, ghost/infra/issuer/monero-release.pin, and everything that fetches Monero binaries reads
# it and checks the archive against it before using it.
#   - The pin file is well-formed: exactly one `version vA.B.C.D` line and one `url https://…/`
#     line, then `archive <platform> <file> <sha256> <directory>` lines: the file is
#     monero-<platform>-<version>.(tar.bz2|zip), the directory ends in -<version>, the hash is 64
#     lowercase hex digits; platforms, files and hashes are distinct; a linux-x64 archive exists
#     (the monero-regtest job downloads it). No other line.
#   - No other file of ghost/ or .github/workflows holds one of its hashes, in any letter case.
#   - A file fetches Monero binaries when it names a Monero download host (downloads, dlsrc or
#     updates.getmonero.org, a getmonero.org /cli/ or /gui/ path), a GitHub release download of
#     monero-project/monero, or a Monero archive name (versioned, or built from variables after a
#     platform family); when one of its lines runs a download command on a getmonero.org URL; or,
#     under infra/issuer and .github/workflows, when it names monerod or monero-wallet-rpc and runs a
#     download command. Every issuer Dockerfile (infra/issuer/Dockerfile*) is such a file by path:
#     the issuer image takes its Monero binaries from the pinned tarball (§6.7). Such a file names
#     the pin outside comments, holds neither a SHA-256-like value nor a Monero archive name of its
#     own (it reads both from the pin), and runs `sha256sum -c` outside comments after its last
#     download and before its first extraction.
#   - The issuer Dockerfiles and compose files use no Monero image of their own (FROM, image: or
#     COPY --from= naming a Monero image reference): Monero binaries come only from the pin.
#   - .github/workflows/monero-regtest.yml exists, names the pin outside comments, checks the
#     archive with `sha256sum -c` after the download and before the extraction, and runs on pull
#     requests touching the issuer, its infrastructure and the Rust workspace manifests
#     (ghost/Cargo.lock, ghost/Cargo.toml: the rail's HTTP, digest and JSON behaviour comes from the
#     locked dependencies).
# Comment lines (first non-blank character `#`) and YAML `name:` lines never satisfy a rule.
# Skipped: build outputs, this gate and test-harness/gates (its fixtures). Fixture roots mirror the
# repository: GHOST_ROOT=<root>/ghost, workflows in <root>/.github/workflows
# (test-harness/gates/monero-pin/README.md).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
# One spelling of every path, so file names print relative to the repository.
GHOST_ROOT="$(cd "$GHOST_ROOT" && pwd)"
PIN_NAME="monero-release.pin"
PIN_REL="infra/issuer/$PIN_NAME"
PIN="$GHOST_ROOT/$PIN_REL"
INFRA="$GHOST_ROOT/infra/issuer"
SELF="$GHOST_ROOT/scripts/gates/monero-pin.sh"
REPO_ROOT="$(cd "$GHOST_ROOT/.." && pwd)"
WORKFLOWS="$REPO_ROOT/.github/workflows"
JOB="$WORKFLOWS/monero-regtest.yml"
JOB_REL=".github/workflows/monero-regtest.yml"
# Pull-request paths the regtest job must run on (§13.6, §19.17 point 7, and the lockfile).
JOB_PATHS=("ghost/issuer/**" "ghost/infra/issuer/**" "ghost/Cargo.lock" "ghost/Cargo.toml")
ARCHIVE_REGEX='monero-[a-z0-9]+-[a-z0-9]+-v[0-9]+(\.[0-9]+){3}\.(tar\.bz2|zip)'
# An archive name built from variables: a platform family, then anything up to the extension.
TEMPLATED_REGEX="monero-(linux|win|mac|android|freebsd)-[^[:space:]\"'/]*\\.(tar\\.bz2|zip)"
HOST_REGEX='(downloads|dlsrc|updates)\.getmonero\.org|getmonero\.org/(cli|gui)/|monero-project/monero/releases/download'
FETCH_REGEX="$HOST_REGEX|$ARCHIVE_REGEX|$TEMPLATED_REGEX"
DOWNLOAD_REGEX='(^|[^[:alnum:]_-])(curl|wget)([[:space:]]|$)|(^|[[:space:]])ADD[[:space:]]+https?://'
BINARY_REGEX='(^|[^[:alnum:]_-])(monerod|monero-wallet-rpc)([^[:alnum:]_-]|$)'
HASH_REGEX='(^|[^0-9A-Fa-f])[0-9A-Fa-f]{64}([^0-9A-Fa-f]|$)'

# Files of ghost/ and .github/workflows matching grep's pattern ($1: -E or -F, $2: pattern), except
# the pin, this gate, build outputs and the gate fixtures; absolute paths.
scan() {
  {
    grep -rIl "$1" -i --exclude-dir=target --exclude-dir=build --exclude-dir=.gradle --exclude-dir=.git \
      -e "$2" "$GHOST_ROOT" 2>/dev/null || true
    if [ -d "$WORKFLOWS" ]; then grep -rIl "$1" -i -e "$2" "$WORKFLOWS" 2>/dev/null || true; fi
  } | grep -v -F -e "$GHOST_ROOT/test-harness/gates/" | grep -v -x -F -e "$PIN" -e "$SELF" | sort -u || true
}
rel() { printf '%s' "${1#"$REPO_ROOT"/}"; }
# The lines of a file that can satisfy a rule: no comment lines, no YAML `name:` lines.
code() { grep -v -E '^[[:space:]]*(#|-?[[:space:]]*name:)' "$1" || true; }

# Where the sha256sum -c check of a file lies: `ok` (after the last download and before the first
# extraction, positions compared within a line too), `order` (only elsewhere) or `none`.
check_order() {
  awk '
    function first(s, re) { return match(s, re) ? RSTART : 0 }
    function last(s, re,   off, r) {
      off = 0; r = 0
      while (match(substr(s, off + 1), re)) { r = off + RSTART; off += RSTART + RLENGTH - 1; if (RLENGTH == 0) break }
      return r
    }
    /^[[:space:]]*(#|-?[[:space:]]*name:)/ { next }
    {
      at = NR * 1000000
      d = last($0, "(^|[^[:alnum:]_-])(curl|wget)([[:space:]]|$)|(^|[[:space:]])ADD[[:space:]]+https?://")
      if (d) last_d = at + d
      c = first($0, "(^|[[:space:]|&;(])sha256sum[[:space:]]+(-c|--check)([[:space:]]|$)")
      if (c) checks[++nc] = at + c
      x = first($0, "(^|[^[:alnum:]_-])(tar[[:space:]]([^|;&]*[[:space:]])?(-[A-Za-z]*x[A-Za-z]*|--extract|x[A-Za-z]*)([[:space:]]|$)|unzip([[:space:]]|$))")
      if (x && !first_x) first_x = at + x
    }
    END {
      if (nc == 0) { print "none"; exit }
      for (i = 1; i <= nc; i++) if (checks[i] > last_d && (!first_x || checks[i] < first_x)) { print "ok"; exit }
      print "order"
    }' "$1"
}

# Lines naming a Monero image reference (with a registry path, tag or digest) in FROM, image: or
# COPY --from=: "line".
monero_images() {
  awk '
    /^[[:space:]]*#/ { next }
    {
      ref = ""
      if ($1 == "FROM") { ref = ($2 ~ /^--platform=/) ? $3 : $2 }
      else if ($1 == "image:" || $1 == "-" && $2 == "image:") { ref = ($1 == "image:") ? $2 : $3 }
      else if ($1 == "COPY") { for (i = 2; i <= NF; i++) if ($i ~ /^--from=/) ref = substr($i, 8) }
      gsub(/["\047]/, "", ref)
      if (tolower(ref) ~ /monero/ && ref ~ /[\/:@]/) print NR
    }' "$1"
}

if [ ! -f "$PIN" ]; then
  fail "ghost/$PIN_REL: $PIN_NAME missing"
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

# The files that fetch Monero binaries (see the header), absolute paths.
fetchers() {
  {
    scan -E "$FETCH_REGEX"
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      if code "$f" | grep -iE "$DOWNLOAD_REGEX" | grep -qi 'getmonero\.org'; then printf '%s\n' "$f"; fi
    done < <(scan -F "getmonero.org")
    for f in "$INFRA"/* "$WORKFLOWS"/*; do
      [ -f "$f" ] || continue
      if code "$f" | grep -qE "$BINARY_REGEX" && code "$f" | grep -qE "$DOWNLOAD_REGEX"; then printf '%s\n' "$f"; fi
    done
    for f in "$INFRA"/Dockerfile*; do [ -f "$f" ] && printf '%s\n' "$f"; done
  } | grep -v -x -F -e "$PIN" -e "$SELF" | sort -u || true
}

# A fetcher reads the pin and pins nothing itself.
own_values() { # $1 = file, $2 = repository-relative name
  while IFS= read -r hit; do
    [ -n "$hit" ] && fail "$2:${hit%%:*}: a Monero archive name of its own: read it from ghost/$PIN_REL"
  done < <(grep -nE "$ARCHIVE_REGEX|$TEMPLATED_REGEX" "$1" || true)
  while IFS= read -r hit; do
    [ -n "$hit" ] && fail "$2:${hit%%:*}: a SHA-256-like value in a file that fetches Monero: read it from ghost/$PIN_REL"
  done < <(grep -nE "$HASH_REGEX" "$1" || true)
}

while IFS= read -r f; do
  [ -n "$f" ] || continue
  [ "$f" = "$JOB" ] && continue
  r="$(rel "$f")"
  code "$f" | grep -qF "$PIN_NAME" || fail "$r: fetches Monero binaries without reading ghost/$PIN_REL"
  own_values "$f" "$r"
  case "$(check_order "$f")" in
    none) fail "$r: fetches Monero binaries without checking them with sha256sum -c" ;;
    order) fail "$r: checks Monero binaries with sha256sum -c only before their download or after their extraction" ;;
  esac
done < <(fetchers)

# No Monero image of their own in the issuer's Dockerfiles and compose files.
for f in "$INFRA"/Dockerfile* "$INFRA"/docker-compose*.yml "$INFRA"/docker-compose*.yaml; do
  [ -f "$f" ] || continue
  while IFS= read -r line_no; do
    [ -n "$line_no" ] && fail "$(rel "$f"):$line_no: a Monero image not built from ghost/$PIN_REL"
  done < <(monero_images "$f")
done

# The pull-request paths of a workflow file, one per line.
pr_paths() {
  awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    { match($0, /^[[:space:]]*/); ind = RLENGTH }
    in_pr && ind <= pr_ind { in_pr = 0; in_paths = 0 }
    in_paths && ind <= paths_ind { in_paths = 0 }
    in_paths && /^[[:space:]]*-[[:space:]]/ {
      v = $0; sub(/^[[:space:]]*-[[:space:]]*/, "", v); sub(/[[:space:]]+#.*$/, "", v); gsub(/["\047[:space:]]/, "", v)
      print v; next
    }
    in_pr && /^[[:space:]]*paths:[[:space:]]*$/ { in_paths = 1; paths_ind = ind; next }
    /^[[:space:]]*pull_request:[[:space:]]*$/ { in_pr = 1; pr_ind = ind; next }
  ' "$1"
}

# The regtest job reads the pin, checks the archive against it and runs on the named paths.
if [ ! -f "$JOB" ]; then
  fail "$JOB_REL: the regtest workflow is missing"
else
  code "$JOB" | grep -qF "$PIN_REL" || fail "$JOB_REL: does not read ghost/$PIN_REL"
  own_values "$JOB" "$JOB_REL"
  case "$(check_order "$JOB")" in
    none) fail "$JOB_REL: does not check the archive with sha256sum -c" ;;
    order) fail "$JOB_REL: checks the archive with sha256sum -c only before its download or after its extraction" ;;
  esac
  paths="$(pr_paths "$JOB")"
  for p in "${JOB_PATHS[@]}"; do
    printf '%s\n' "$paths" | grep -qx -F -e "$p" || fail "$JOB_REL: pull_request paths miss $p"
  done
fi
finish monero-pin
