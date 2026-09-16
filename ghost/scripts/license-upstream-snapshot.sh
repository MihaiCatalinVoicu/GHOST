#!/usr/bin/env bash
# Rewrites the upstream licence snapshot, ghost/licenses/upstream/ (ADR-37; Phase 9 design §22.8.10
# point 3). A maintainer tool, run with network access (GitHub CLI `gh`, authenticated) whenever the
# licence gates report a missing entry; the result is committed and reviewed. The gates themselves
# never reach the network: they read the snapshot.
#   - Every Rust package of a shipped graph used under Apache-2.0 (licenses.pl upstream-candidates):
#     the NOTICE files (any file whose name starts with NOTICE) of its repository at the commit it
#     was published from (.cargo_vcs_info.json), in the package's directory and at the repository
#     root. Apache-2.0 §4(d) makes a NOTICE file part of what a distribution carries; a crate archive
#     may leave it out.
#   - Every Gradle component named in ghost/licenses/upstream/maven-sources.txt: the named files of
#     its repository at its release tag, for libraries whose artifacts carry no licence text.
# Index lines: <ecosystem> <name> <version> <repository> <commit> none
#              <ecosystem> <name> <version> <repository> <commit> captured (<path> <sha256>)...
# Captured files are stored as upstream/<ecosystem>/<name, ':' as '__'>-<version>/<path, '/' as '__'>.
# Usage: license-upstream-snapshot.sh (from anywhere; needs cargo, perl, gh).
set -euo pipefail
GHOST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export GHOST_ROOT
UP="$GHOST_ROOT/licenses/upstream"
command -v gh >/dev/null || { echo "gh (GitHub CLI) is required" >&2; exit 2; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

github_repo() { # $1 = repository URL -> owner/repo
  local u="${1%.git}"
  u="${u%/}"
  case "$u" in
    https://github.com/*/*) echo "${u#https://github.com/}" | cut -d/ -f1-2 ;;
    *) return 1 ;;
  esac
}
store_path() { # $1 ecosystem, $2 name, $3 version, $4 path
  printf '%s/%s/%s-%s/%s' "$UP" "$1" "${2//:/__}" "$3" "${4//\//__}"
}
fetch_raw() { # $1 owner/repo, $2 path, $3 ref, $4 output
  gh api -H "Accept: application/vnd.github.raw" "repos/$1/contents/$2?ref=$3" > "$4"
}
notice_names() { # $1 owner/repo, $2 directory ("" = root), $3 ref; fails when the listing cannot be read
  local listing
  listing="$(gh api "repos/$1/contents${2:+/$2}?ref=$3" --jq '.[] | select(.type == "file") | .path')"
  printf '%s\n' "$listing" | awk -F/ '{n = $NF} n ~ /^NOTICE/ {print}'
}

index="$work/index.txt"
{
  echo "# Upstream licence snapshot (scripts/license-upstream-snapshot.sh; ADR-37, Phase 9 design §22.8.10 point 3)."
  echo "# Written $(date -u +%Y-%m-%d); reviewed with the commit that changes it."
} > "$index"
rm -rf "$work/files"
mkdir -p "$work/files"

cd "$GHOST_ROOT"
cargo fetch --locked >/dev/null
perl scripts/gates/licenses.pl upstream-candidates > "$work/candidates.tsv"
while IFS=$'\t' read -r eco name version repo commit path; do
  [ -n "$name" ] || continue
  if ! slug="$(github_repo "$repo")" || [ "$commit" = "-" ]; then
    echo "$name $version: repository '$repo' at '$commit' cannot be read here; review it by hand" >&2
    exit 1
  fi
  names="$(notice_names "$slug" "" "$commit")"
  if [ -n "$path" ]; then names="$(printf '%s\n%s\n' "$names" "$(notice_names "$slug" "$path" "$commit")" | awk NF | sort -u)"; fi
  if [ -z "$names" ]; then
    echo "$eco $name $version $repo $commit none" >> "$index"
    continue
  fi
  line="$eco $name $version $repo $commit captured"
  while IFS= read -r f; do
    out="$(store_path "$eco" "$name" "$version" "$f")"
    out="$work/files/${out#"$UP"/}"
    mkdir -p "$(dirname "$out")"
    fetch_raw "$slug" "$f" "$commit" "$out"
    line="$line $f $(sha256sum "$out" | cut -d' ' -f1)"
  done <<< "$names"
  echo "$line" >> "$index"
done < "$work/candidates.tsv"

while read -r coord version repo ref files; do
  case "$coord" in ''|'#'*) continue ;; esac
  slug="$(github_repo "$repo")"
  commit="$(gh api "repos/$slug/commits/$ref" --jq .sha)"
  line="maven $coord $version $repo $commit captured"
  for f in ${files//,/ }; do
    out="$(store_path maven "$coord" "$version" "$f")"
    out="$work/files/${out#"$UP"/}"
    mkdir -p "$(dirname "$out")"
    fetch_raw "$slug" "$f" "$commit" "$out"
    line="$line $f $(sha256sum "$out" | cut -d' ' -f1)"
  done
  echo "$line" >> "$index"
done < "$UP/maven-sources.txt"

rm -rf "$UP/cargo" "$UP/maven"
cp -r "$work/files/." "$UP/"
cp "$index" "$UP/index.txt"
echo "upstream snapshot: $(grep -vc '^#' "$UP/index.txt") entries in $UP/index.txt" >&2
