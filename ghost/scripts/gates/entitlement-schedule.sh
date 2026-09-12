#!/usr/bin/env bash
# Gate (Phase 8 design §3.1, §14.1, §19.2, §19.12, §19.17): the Entitlement Schedule.
#  - ghost/protocol/entitlement/schedule.ghes verifies under the schedule key pinned in
#    ghost-entitlement for its network (`ghost-issuer-ops schedule-verify`, which runs
#    Schedule::verify: rules 1-4, including the >= 26-week horizon counted from the schedule's own
#    first week, so nothing depends on the build date, T12);
#  - rule 5 over the whole first-parent history: every version committed before, oldest first, is
#    checked against all versions before it and the file against all of them (`--previous`
#    repeated), as a verifier that accepted each version in turn would: same network, keys, slot
#    sets of covered weeks, prices and revocations unchanged, key ids and moduli distinct, seq not
#    backwards. CI runs on the pushed head only and a push or a fast-forward merge can bring several
#    versions at once, so no version counts as checked because it was once the head;
#  - every slot onion of the current and the next week is listed in the relay directory
#    (protocol/entitlement/relay-directory.txt, `relay <onion:port> <operator id hex>`), and three
#    slots of the week can be chosen whose relays span at least two operators (§19.12);
#  - one path: no other *.ghes file under GHOST_ROOT, and no sealed key file (*.ghks) or key load
#    file (*.ghkl) at all (issuer keys are never committed). Skipped are only the gate fixture roots
#    (test-harness/gates), the issuer crates' committed test fixtures (issuer/crates/*/tests/fixtures)
#    and build outputs where a build file makes them one (target/ beside a Cargo.toml, build/ beside
#    a build.gradle.kts, .gradle/ and .kotlin/ beside a settings.gradle.kts); any other directory is
#    scanned, whatever its name;
#  - infrastructure names the schedule by its one path: every .ghes path under infra/ resolves to
#    protocol/entitlement/schedule.ghes. A relative path is read against the build context (ghost/)
#    or the repository root, a path with `..` and the source of a `SRC:DST` mapping (a volume)
#    against the file's own directory; an absolute path is an in-container location and, read as a
#    repository path by any of its suffixes (a context-relative COPY source, a build stage's copy of
#    the repository), names no other repository file. Paths through variables, `~`, escapes or
#    globs, and URLs, are refused: no check could tie them to the schedule;
#  - test material stays out of production: no production source (src/ of the Rust crates,
#    build.rs, Android src/main) names a tests/fixtures or test-harness/gates path or a test fixture
#    file.
# Before slice S2b commits the first schedule the file is absent. The gate then passes and says
# so, but only while the file has never been committed on the first-parent history: once
# committed, its absence fails. The exit-gate checklist (§15.2) requires the committed schedule.
# Needs the git history (CI: fetch-depth 0) and, when the schedule exists, cargo.
# Self-test hooks, honoured for fixture roots only (GHOST_ROOT other than this repository's ghost/):
#   GHOST_ES_TEST_KEY=<hex>      verify under this schedule key instead of the pinned one;
#   GHOST_ES_PREDECESSOR=<file>  a history of this one version instead of the git lookup
#                                ("committed before");
#   GHOST_ES_GIT=1               the history from the git repository holding the fixture root (the
#                                self-test builds throwaway repositories);
#   GHOST_ES_NOW=<unix seconds>  the instant of the relay directory check.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
ES_REL="protocol/entitlement/schedule.ghes"
DIR_REL="protocol/entitlement/relay-directory.txt"
ES="$GHOST_ROOT/$ES_REL"
DIRECTORY="$GHOST_ROOT/$DIR_REL"
REAL_ROOT="$(cd "$GATES_DIR/../.." && pwd -P)"
fixture_root=0
[ "$(cd "$GHOST_ROOT" && pwd -P)" = "$REAL_ROOT" ] || fixture_root=1
if [ "$fixture_root" = 0 ]; then
  for hook in GHOST_ES_TEST_KEY GHOST_ES_PREDECESSOR GHOST_ES_GIT GHOST_ES_NOW; do
    if [ -n "${!hook:-}" ]; then echo "$hook is a self-test hook for fixture roots only" >&2; exit 2; fi
  done
fi
if [ -n "${GHOST_ES_GIT:-}" ] && [ -n "${GHOST_ES_PREDECESSOR:-}" ]; then
  echo "GHOST_ES_GIT and GHOST_ES_PREDECESSOR exclude each other" >&2; exit 2
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The trees the one-path and key checks skip (see the header), one path per line.
skipped_trees() {
  local d f
  printf '%s\n' "$GHOST_ROOT/test-harness/gates"
  for d in "$GHOST_ROOT"/issuer/crates/*/; do printf '%s\n' "${d}tests/fixtures"; done
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    d="${f%/*}"
    case "${f##*/}" in
      Cargo.toml) printf '%s\n' "$d/target" ;;
      build.gradle.kts) printf '%s\n' "$d/build" ;;
      settings.gradle.kts) printf '%s\n' "$d/.gradle" "$d/.kotlin" ;;
    esac
  done < <(find "$GHOST_ROOT" \( -path "$GHOST_ROOT/test-harness/gates" -o -name target -o -name build \
    -o -name .gradle -o -name .kotlin \) -prune -o -type f \
    \( -name Cargo.toml -o -name build.gradle.kts -o -name settings.gradle.kts \) -print 2>/dev/null || true)
}
prune=()
while IFS= read -r d; do
  [ "${#prune[@]}" -eq 0 ] || prune+=(-o)
  prune+=(-path "$d")
done < <(skipped_trees)
outside_fixtures() { # files under GHOST_ROOT matching the find expression in "$@", skipped trees excluded
  find "$GHOST_ROOT" \( "${prune[@]}" \) -prune -o -type f \( "$@" \) -print 2>/dev/null || true
}

# One path, no second copy; issuer key material is never committed.
while IFS= read -r f; do
  [ -n "$f" ] && [ "$f" != "$ES" ] || continue
  fail "${f#"$GHOST_ROOT"/}: an Entitlement Schedule outside $ES_REL (one path, no second copy)"
done < <(outside_fixtures -name '*.ghes')
while IFS= read -r f; do
  [ -n "$f" ] || continue
  fail "${f#"$GHOST_ROOT"/}: sealed key or key load file outside tests/fixtures (issuer keys are never committed)"
done < <(outside_fixtures -name '*.ghks' -o -name '*.ghkl')

# A /-separated path with "." and ".." resolved lexically and repeated "/" collapsed; fails when
# ".." climbs above the start of the path.
normalize() {
  local IFS=/ seg lead="" out=() segs=()
  [[ "$1" == /* ]] && lead=/
  read -r -a segs <<< "$1"
  for seg in ${segs[@]+"${segs[@]}"}; do
    case "$seg" in
      '' | .) ;;
      ..)
        [ "${#out[@]}" -gt 0 ] || return 1
        unset 'out[${#out[@]}-1]'
        ;;
      *) out+=("$seg") ;;
    esac
  done
  printf '%s%s\n' "$lead" "${out[*]-}"
}

# Checks one .ghes token found at $1 (a file under infra/), line $2 (see the header).
infra_reference() {
  local file="$1" line="$2" token="$3" rel dir parts part i n resolved suffix
  rel="${file#"$GHOST_ROOT"/}"
  dir="${rel%/*}"
  case "$token" in
    *'$'* | *'{'* | *'}'* | *'~'* | *'\'* | *'*'* | *'?'*)
      fail "$rel:$line: '$token' cannot be resolved (variable, home, escape or glob): infra must name $ES_REL literally"
      return ;;
    *://*)
      fail "$rel:$line: '$token' is a URL: infra must take $ES_REL from the repository"
      return ;;
  esac
  IFS=: read -r -a parts <<< "$token"
  n="${#parts[@]}"
  for ((i = 0; i < n; i++)); do
    part="${parts[i]}"
    [[ "$part" == *.ghes ]] || continue
    if [ "$i" -lt $((n - 1)) ]; then
      # The source of a SRC:DST mapping: a host path relative to this file.
      if [[ "$part" == /* ]] || ! resolved="$(normalize "$dir/$part")" || [ "$resolved" != "$ES_REL" ]; then
        fail "$rel:$line: '$part' is not $ES_REL (a mapped source, read relative to $dir)"
      fi
    elif [[ "$part" == //* ]]; then
      fail "$rel:$line: '$part' is a network path: infra must take $ES_REL from the repository"
    elif [[ "$part" == /* ]]; then
      # An in-container location that names no other repository file by any of its suffixes.
      if ! resolved="$(normalize "$part")"; then
        fail "$rel:$line: '$part' climbs above /"
        continue
      fi
      suffix="${resolved#/}"
      while [ -n "$suffix" ]; do
        if [ "$suffix" != "$ES_REL" ] && [ -e "$GHOST_ROOT/$suffix" ]; then
          fail "$rel:$line: '$part' names the repository file $suffix, not $ES_REL"
          break
        fi
        [[ "$suffix" == */* ]] || break
        suffix="${suffix#*/}"
      done
    elif [[ "/$part/" == */../* ]]; then
      if ! resolved="$(normalize "$dir/$part")" || [ "$resolved" != "$ES_REL" ]; then
        fail "$rel:$line: '$part' is not $ES_REL (read relative to $dir; infra must reference the one schedule)"
      fi
    else
      resolved="$(normalize "$part")"
      case "$resolved" in
        "$ES_REL" | "ghost/$ES_REL") ;;
        *) fail "$rel:$line: '$part' is not $ES_REL (infra must reference the one schedule)" ;;
      esac
    fi
  done
}

# Infrastructure names the schedule by its one repository path. A token runs up to ".ghes" through
# every character but blanks, quotes and shell or YAML separators, so a variable or a URL stays in it.
TOKEN_RE='[^][:space:]"'"'"'`,;()<>|&=[]*\.ghes'
if [ -d "$GHOST_ROOT/infra" ]; then
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    file="${hit%%:*}"; rest="${hit#*:}"; line="${rest%%:*}"; token="${rest#*:}"
    infra_reference "$file" "$line" "$token"
  done < <(grep -rnoIE "$TOKEN_RE" "$GHOST_ROOT/infra" 2>/dev/null || true)
fi

# Production sources never name test material.
FIXTURE_REGEX='tests/fixtures|test-harness/gates|test_schedule\.(ghes|source)|test_keys\.txt'
production_sources() {
  find "$GHOST_ROOT/relay" "$GHOST_ROOT/client-core" "$GHOST_ROOT/issuer" -path '*/target' -prune -o \
    -type f \( -name build.rs -o \( -name '*.rs' -path '*/src/*' \) \) -print 2>/dev/null || true
  android_main_files
}
while IFS= read -r f; do
  [ -n "$f" ] || continue
  hits="$(grep -nE -- "$FIXTURE_REGEX" "$f" || true)"
  [ -z "$hits" ] || while IFS= read -r l; do fail "$f:$l: production source names test material"; done <<< "$hits"
done < <(production_sources)

# The history (rule 5): every committed version of the file, oldest first, without the file itself.
history=()
committed_before=0
use_git=0
if [ "$fixture_root" = 0 ] || [ -n "${GHOST_ES_GIT:-}" ]; then
  use_git=1
elif [ -n "${GHOST_ES_PREDECESSOR:-}" ]; then
  history=("$GHOST_ES_PREDECESSOR")
  committed_before=1
fi
if [ "$use_git" = 1 ]; then
  command -v git >/dev/null || { echo "git not found" >&2; exit 2; }
  if ! prefix="$(git -C "$GHOST_ROOT" rev-parse --show-prefix 2>/dev/null)"; then
    fail "$GHOST_ROOT is not a git work tree: rule 5 needs the history of $ES_REL"
    finish entitlement-schedule
  fi
  if [ "$(git -C "$GHOST_ROOT" rev-parse --is-shallow-repository)" = true ]; then
    fail "shallow clone: rule 5 needs the whole history of $ES_REL (checkout with fetch-depth: 0)"
    finish entitlement-schedule
  fi
  commits="$(git -C "$GHOST_ROOT" log --first-parent --reverse --format=%H -- "$ES_REL")" || { fail "git log failed"; finish entitlement-schedule; }
  n=0
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    git -C "$GHOST_ROOT" cat-file -e "$c:$prefix$ES_REL" 2>/dev/null || continue
    committed_before=1
    n=$((n + 1))
    version="$work/version-$n.ghes"
    git -C "$GHOST_ROOT" cat-file blob "$c:$prefix$ES_REL" > "$version"
    # The same bytes again right after (a merge bringing them, a file removed and restored) are the
    # same version; a return to an older version after a different one is a new version.
    if [ "${#history[@]}" -gt 0 ] && cmp -s "${history[${#history[@]}-1]}" "$version"; then continue; fi
    history+=("$version")
  done <<< "$commits"
  # The last committed version, when the file still has its bytes, is the schedule itself; an
  # edit since is checked against every committed version.
  if [ -f "$ES" ] && [ "${#history[@]}" -gt 0 ] && cmp -s "${history[${#history[@]}-1]}" "$ES"; then
    unset 'history[${#history[@]}-1]'
  fi
fi

if [ ! -f "$ES" ]; then
  if [ "$committed_before" = 1 ]; then
    fail "$ES_REL was committed before and is now missing (a published schedule is never removed)"
  else
    echo "[entitlement-schedule] $ES_REL absent and never committed: slice S2b (the first stagenet schedule) is pending"
  fi
  # finish exits only on failure.
  finish entitlement-schedule
  exit 0
fi
[ -f "$DIRECTORY" ] || fail "$DIR_REL missing: the slot onions of the schedule are checked against it (§19.12)"

command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 2; }
args=(schedule-verify --schedule "$ES")
[ -z "${GHOST_ES_TEST_KEY:-}" ] || args+=(--schedule-public-key "$GHOST_ES_TEST_KEY")
for version in ${history[@]+"${history[@]}"}; do args+=(--previous "$version"); done
[ ! -f "$DIRECTORY" ] || args+=(--relay-directory "$DIRECTORY" --now "${GHOST_ES_NOW:-$(date +%s)}")
if out="$(cargo run --locked --quiet --manifest-path "$REAL_ROOT/Cargo.toml" -p ghost-issuer-ops -- "${args[@]}" 2>&1)"; then
  printf '%s\n' "$out"
else
  printf '%s\n' "$out" >&2
  fail "ghost-issuer-ops schedule-verify refused $ES_REL"
fi
[ "${#history[@]}" -gt 0 ] || echo "[entitlement-schedule] no earlier version of $ES_REL: rule 5 has no predecessor (first schedule)"
finish entitlement-schedule
