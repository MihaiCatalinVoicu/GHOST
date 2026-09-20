#!/usr/bin/env bash
# Gate G-DM6 (Phase 9 design §13.6 R-M4, §10.7 "No FTS", invariants T25 and T33; mutant ME-18
# "an FTS index present"): **production SQL carries no `CREATE VIRTUAL TABLE` and no `fts` token.**
#
# Why a gate and not only a schema test. `Migration5Test.theSchemaCarriesNoVirtualTable` reads
# `sqlite_master` of a migrated database, which proves what the *migrations* create. It cannot see
# a virtual table a DAO creates at runtime, one created in a later migration that no test opens,
# or an FTS table created on a side connection. This gate reads the text instead, so any route to
# a virtual table fails before the database is ever opened.
#
# Why "no FTS index" is a privacy rule and not a performance preference: SQLite's `secure_delete`
# does not scrub an FTS shadow table (§10.7). A message deleted at its expiry would leave its
# words behind in `*_content` and `*_segments`, which is exactly the residue T25 (physical
# deletion) and T33 (local forensic minimality) exist to refuse, and R-M1's dump would show it.
#
# What counts as production SQL:
#   - every Kotlin and Java source on the Android production path (`*/src/main/*`, from
#     `android_main_files` — the schema, the migrations and every DAO live there), and
#   - every `*.sql` file of the monorepo outside build outputs and test trees.
# Test sources are excluded on purpose: a test may name FTS to prove it is absent, and
# `Migration5Test` does.
#
# The `fts` token is matched as a token, not as a substring: `fts`, `FTS5`, `fts_content` and
# `ftsIndex` are reported, while `shifts`, `drafts`, `lifts` and `gifts` are not. A **comment**
# that merely mentions FTS in a production source fails too, and deliberately: the rule the gates
# table states is that the token does not appear in production SQL, and a gate that had to tell a
# comment from a statement would be a SQL parser with a parser's blind spots. Say it in the design
# document or in a test instead.
#
# Vacuity is checked twice, because a gate that scans nothing passes: at least one production
# source must be found, and at least one of them must contain a `CREATE TABLE` — if the schema
# ever moves out of `android/*/src/main`, this gate must fail rather than go quiet.
#
# Usage: dm-no-fts.sh        (scans GHOST_ROOT, default: the ghost/ monorepo)
# Self-test: scripts/gates/self-test.sh points GHOST_ROOT at test-harness/gates/negative-dm-fts-*.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# `CREATE   VIRTUAL\n TABLE` counts: any run of whitespace between the words.
VIRTUAL_TABLE='CREATE[[:space:]]+VIRTUAL[[:space:]]+TABLE'
# A token boundary before `fts`, none needed after it (`fts5`, `fts_content`, `ftsIndex`).
FTS_TOKEN='(^|[^A-Za-z0-9])fts'
CREATE_TABLE='CREATE[[:space:]]+TABLE'

# Every `*.sql` file of the monorepo, build outputs pruned. Test trees are filtered out by
# [is_test_path] against the path *relative to GHOST_ROOT*, so a fixture root that itself sits
# under test-harness/ is still scanned.
sql_files() {
  find "$GHOST_ROOT" -type d \( -name build -o -name target -o -name .git \) -prune -o \
    -type f -name '*.sql' -print 2>/dev/null || true
}

is_test_path() { # $1 = path relative to GHOST_ROOT
  case "/$1" in
    */src/test/*|*/src/androidTest/*|*/src/testFixtures/*|*/tests/*|/test-harness/*) return 0 ;;
  esac
  return 1
}

SCANNED=0
WITH_CREATE_TABLE=0
while IFS= read -r file; do
  [ -n "$file" ] || continue
  rel="${file#"$GHOST_ROOT"/}"
  is_test_path "$rel" && continue
  SCANNED=$((SCANNED + 1))
  # Each hit is read from a variable with a here-string, never `producer | grep -q`: under
  # `set -o pipefail` such a pipeline fails whenever grep stops reading early (EPIPE), which is
  # the race the static-gate sweep of 2026-09-20 removed from four other gates.
  hits="$(grep -niE -- "$VIRTUAL_TABLE" "$file" || true)"
  if [ -n "$hits" ]; then
    while IFS= read -r line; do
      fail "$rel:$line (R-M4: no CREATE VIRTUAL TABLE in production SQL)"
    done <<< "$hits"
  fi
  hits="$(grep -niE -- "$FTS_TOKEN" "$file" || true)"
  if [ -n "$hits" ]; then
    while IFS= read -r line; do
      fail "$rel:$line (R-M4: no 'fts' token in production SQL; secure_delete does not scrub FTS shadow tables)"
    done <<< "$hits"
  fi
  if grep -qiE -- "$CREATE_TABLE" "$file"; then
    WITH_CREATE_TABLE=$((WITH_CREATE_TABLE + 1))
  fi
done < <({ android_main_files; sql_files; })

[ "$SCANNED" -gt 0 ] || fail "no production SQL sources found under $GHOST_ROOT (the gate would pass vacuously)"
[ "$WITH_CREATE_TABLE" -gt 0 ] || \
  fail "none of the $SCANNED scanned production sources contains a CREATE TABLE (the gate would pass vacuously)"

finish dm-no-fts
