#!/usr/bin/env bash
# Gate (Phase 8 design §3.1, §14.1, §19.2, §19.12, §19.17): the Entitlement Schedule.
#  - ghost/protocol/entitlement/schedule.ghes verifies under the schedule key pinned in
#    ghost-entitlement for its network (`ghost-issuer-ops schedule-verify`, which runs
#    Schedule::verify: rules 1-4, including the >= 26-week horizon counted from the schedule's own
#    first week, so nothing depends on the build date, T12);
#  - rule 5 against its predecessor in git, the most recent different version on the first-parent
#    history: same network, keys, slot sets of covered weeks, prices and revocations unchanged, key
#    ids and moduli distinct, seq not backwards;
#  - every slot onion of the current and the next week is listed in the relay directory
#    (protocol/entitlement/relay-directory.txt, `relay <onion:port> <operator id hex>`), and three
#    slots of the week can be chosen whose relays span at least two operators (§19.12);
#  - one path: no other *.ghes file outside tests/fixtures and test-harness, and every repository
#    path to a .ghes file under infra/ is protocol/entitlement/schedule.ghes (absolute paths are
#    in-container locations);
#  - test material stays out of production: no production source (src/ of the Rust crates,
#    build.rs, Android src/main) names a tests/fixtures or test-harness/gates path or a test fixture
#    file, and no sealed key file (*.ghks) or key load file (*.ghkl) exists outside tests/fixtures
#    and test-harness.
# Before slice S2b commits the first schedule the file is absent. The gate then passes and says
# so, but only while the file has never been committed on the first-parent history: once
# committed, its absence fails. The exit-gate checklist (§15.2) requires the committed schedule.
# Needs the git history (CI: fetch-depth 0) and, when the schedule exists, cargo.
# Self-test hooks, honoured for fixture roots only (GHOST_ROOT other than this repository's ghost/):
#   GHOST_ES_TEST_KEY=<hex>      verify under this schedule key instead of the pinned one;
#   GHOST_ES_PREDECESSOR=<file>  the predecessor instead of the git lookup ("committed before");
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
  for hook in GHOST_ES_TEST_KEY GHOST_ES_PREDECESSOR GHOST_ES_NOW; do
    if [ -n "${!hook:-}" ]; then echo "$hook is a self-test hook for fixture roots only" >&2; exit 2; fi
  done
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

outside_fixtures() { # files under GHOST_ROOT matching the find expression in "$@", fixtures excluded
  find "$GHOST_ROOT" \( -path "$GHOST_ROOT/test-harness" -o -path "$GHOST_ROOT/target" \
    -o -path '*/tests/fixtures' -o -name build -o -name .gradle \) -prune -o -type f \( "$@" \) -print 2>/dev/null || true
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

# Infrastructure names the schedule by its one repository path.
if [ -d "$GHOST_ROOT/infra" ]; then
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    file="${hit%%:*}"; rest="${hit#*:}"; line="${rest%%:*}"; token="${rest#*:}"
    case "$token" in
      /*|*"$ES_REL") ;;
      *) fail "${file#"$GHOST_ROOT"/}:$line: '$token' is not $ES_REL (infra must reference the one schedule)" ;;
    esac
  done < <(grep -rnoE '[A-Za-z0-9_./~-]*\.ghes' "$GHOST_ROOT/infra" 2>/dev/null || true)
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

# The predecessor: the most recent committed version that differs from the file (rule 5).
predecessor=""
committed_before=0
if [ "$fixture_root" = 1 ]; then
  if [ -n "${GHOST_ES_PREDECESSOR:-}" ]; then predecessor="$GHOST_ES_PREDECESSOR"; committed_before=1; fi
else
  command -v git >/dev/null || { echo "git not found" >&2; exit 2; }
  if ! prefix="$(git -C "$GHOST_ROOT" rev-parse --show-prefix 2>/dev/null)"; then
    fail "$GHOST_ROOT is not a git work tree: rule 5 needs the history of $ES_REL"
    finish entitlement-schedule
  fi
  if [ "$(git -C "$GHOST_ROOT" rev-parse --is-shallow-repository)" = true ]; then
    fail "shallow clone: rule 5 needs the whole history of $ES_REL (checkout with fetch-depth: 0)"
    finish entitlement-schedule
  fi
  commits="$(git -C "$GHOST_ROOT" log --first-parent --format=%H -- "$ES_REL")" || { fail "git log failed"; finish entitlement-schedule; }
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    git -C "$GHOST_ROOT" cat-file -e "$c:$prefix$ES_REL" 2>/dev/null || continue
    committed_before=1
    git -C "$GHOST_ROOT" cat-file blob "$c:$prefix$ES_REL" > "$work/predecessor.ghes"
    if [ ! -f "$ES" ] || ! cmp -s "$work/predecessor.ghes" "$ES"; then
      predecessor="$work/predecessor.ghes"
      break
    fi
  done <<< "$commits"
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
[ -z "$predecessor" ] || args+=(--previous "$predecessor")
[ ! -f "$DIRECTORY" ] || args+=(--relay-directory "$DIRECTORY" --now "${GHOST_ES_NOW:-$(date +%s)}")
if out="$(cargo run --locked --quiet --manifest-path "$REAL_ROOT/Cargo.toml" -p ghost-issuer-ops -- "${args[@]}" 2>&1)"; then
  printf '%s\n' "$out"
else
  printf '%s\n' "$out" >&2
  fail "ghost-issuer-ops schedule-verify refused $ES_REL"
fi
[ -n "$predecessor" ] || echo "[entitlement-schedule] no earlier version of $ES_REL: rule 5 has no predecessor (first schedule)"
finish entitlement-schedule
