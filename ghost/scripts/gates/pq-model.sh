#!/usr/bin/env bash
# Gate `pq-model` (Phase 9 design §9.5 "Model in CI", §16.2; slice S13): runs every ProVerif model
# of protocol/models/dm and compares each query's result with protocol/models/dm/expected.txt.
#
# A model is listed there line by line as `model | token | expected`, where `token` names exactly
# one `RESULT` line of the model's output and `expected` is `true` (the property is proved) or
# `false` (ProVerif finds the attack — a control query, or every query of a mutant model, which is
# how a model shows it can fail at all). The run fails on:
#   - a result other than the expected one, and `cannot be proved` whatever was expected;
#   - a token that matches no RESULT line, or more than one;
#   - a RESULT line no token of its model matches (a query nobody decided about);
#   - a .pv or .patch file of the directory that expected.txt does not list (a model nobody runs);
#   - a mutant patch that no longer applies to its original, or that changes nothing;
#   - a non-zero exit of ProVerif, or a model that runs past PQ_MODEL_TIMEOUT seconds.
# It complements, and does not replace, the exhaustive state models EM-1 and EM-2 of the `rust`
# job (§15.2).
#
# **Mutants are generated, not copied** (the slice S13 review: two hand-copied mutant models
# differed from their originals only at the mutation on the day they were written, and nothing
# kept it so). A listed model `<original>_mutant_<name>.pv` that is not a file is built from
# `<original>.pv` by `<original>_mutant_<name>.patch` with GNU patch at fuzz 0: an edit to the
# original away from the mutation carries over, an edit that touches the mutated lines' context
# makes the patch fail, and either way the mutant is its original plus one mutation.
#
# Usage: pq-model.sh
# Environment: PROVERIF (the binary, default `proverif`), PQ_MODEL_TIMEOUT (seconds per model,
# default 900), PQ_MODEL_DIR (default protocol/models/dm), PQ_MODEL_EXPECTED (default
# $PQ_MODEL_DIR/expected.txt). The self-test points PROVERIF at test-harness/gates/pq-model/
# fake-proverif.sh, which replays recorded outputs, so the comparison is proven without the tool.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
PROVERIF="${PROVERIF:-proverif}"
TIMEOUT="${PQ_MODEL_TIMEOUT:-900}"
MODEL_DIR="${PQ_MODEL_DIR:-$GHOST_ROOT/protocol/models/dm}"
EXPECTED="${PQ_MODEL_EXPECTED:-$MODEL_DIR/expected.txt}"

[ -d "$MODEL_DIR" ] || { echo "model directory not found: $MODEL_DIR" >&2; exit 2; }
[ -f "$EXPECTED" ] || { echo "expectations not found: $EXPECTED" >&2; exit 2; }
command -v timeout >/dev/null 2>&1 || { echo "coreutils timeout is required" >&2; exit 2; }
command -v patch >/dev/null 2>&1 || { echo "GNU patch is required (mutant models)" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/gen"

# The expectations, comments and blank lines dropped: `model|token|expected`.
grep -vE '^[[:space:]]*(#|$)' "$EXPECTED" > "$work/expected" || true
[ -s "$work/expected" ] || { fail "no expectation read from $EXPECTED"; finish pq-model; }
while IFS= read -r line; do
  model="${line%%|*}"; rest="${line#*|}"; token="${rest%|*}"; want="${rest##*|}"
  if [ -z "$model" ] || [ -z "$token" ] || [ "$rest" = "$line" ] || [ "$token" = "$rest" ]; then
    fail "$EXPECTED: malformed line '$line'"
  elif [ "$want" != true ] && [ "$want" != false ]; then
    fail "$EXPECTED: expected result must be true or false in '$line'"
  fi
done < "$work/expected"

# Every model of the directory is listed, and every listed model exists: a .pv file, or a mutant
# patch that generates it.
cut -d'|' -f1 "$work/expected" | sort -u > "$work/listed"
(cd "$MODEL_DIR" && find . -maxdepth 1 -name '*.pv' -printf '%f\n' 2>/dev/null || ls -1 -- *.pv 2>/dev/null) \
  | sed 's|^\./||' | sort -u > "$work/files"
(cd "$MODEL_DIR" && find . -maxdepth 1 -name '*.patch' -printf '%f\n' 2>/dev/null || ls -1 -- *.patch 2>/dev/null) \
  | sed 's|^\./||' | sort -u > "$work/patches"
while read -r patch_file; do
  [ -n "$patch_file" ] || continue
  model="${patch_file%.patch}.pv"
  case "$model" in
    *_mutant_*) ;;
    *) fail "$MODEL_DIR/$patch_file: a mutant patch is named <original>_mutant_<name>.patch" ;;
  esac
  if grep -qxF -- "$model" "$work/files"; then
    fail "$MODEL_DIR/$patch_file: $model is also a file; a mutant is generated, never copied"
  fi
  echo "$model"
done < "$work/patches" > "$work/generated"
sort -u "$work/files" "$work/generated" > "$work/present"
while read -r model; do
  [ -n "$model" ] && fail "$MODEL_DIR/$model is a model expected.txt does not list"
done < <(comm -13 "$work/listed" "$work/present")
while read -r model; do
  [ -n "$model" ] && fail "expected.txt lists $model, which $MODEL_DIR does not hold"
done < <(comm -23 "$work/listed" "$work/present")

queries=0
models=0
while read -r model; do
  if [ -f "$MODEL_DIR/$model" ]; then
    source_model="$MODEL_DIR/$model"
  elif grep -qxF -- "$model" "$work/generated"; then
    # A mutant: its original plus its patch, applied at fuzz 0.
    original="${model%%_mutant_*}.pv"
    source_model="$work/gen/$model"
    if [ ! -f "$MODEL_DIR/$original" ]; then
      fail "$model: its original $original is not in $MODEL_DIR"
      continue
    fi
    if ! patch --batch --fuzz=0 --quiet --no-backup-if-mismatch \
      --reject-file="$work/gen/$model.rej" -o "$source_model" \
      "$MODEL_DIR/$original" "$MODEL_DIR/${model%.pv}.patch" > "$work/gen/$model.log" 2>&1; then
      fail "$model: ${model%.pv}.patch no longer applies to $original: $(head -n 1 "$work/gen/$model.log")"
      continue
    fi
    if cmp -s "$MODEL_DIR/$original" "$source_model"; then
      fail "$model: ${model%.pv}.patch changes nothing in $original"
      continue
    fi
  else
    continue
  fi
  models=$((models + 1))
  out="$work/$model.out"
  set +e
  timeout "$TIMEOUT" "$PROVERIF" "$source_model" > "$out" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 124 ]; then
    fail "$model: ProVerif ran past ${TIMEOUT}s"
    continue
  elif [ "$rc" -ne 0 ]; then
    fail "$model: ProVerif exited $rc: $(grep -m1 -iE 'error' "$out" || tail -n 1 "$out")"
    continue
  fi
  grep -E '^RESULT ' "$out" > "$work/$model.results" || true
  [ -s "$work/$model.results" ] || { fail "$model: no RESULT line in ProVerif's output"; continue; }
  : > "$work/$model.claimed"
  while IFS= read -r line; do
    [ "${line%%|*}" = "$model" ] || continue
    rest="${line#*|}"; token="${rest%|*}"; want="${rest##*|}"
    matches="$(grep -cF -- "$token" "$work/$model.results" || true)"
    if [ "$matches" != 1 ]; then
      fail "$model: '$token' names $matches RESULT lines, not exactly one"
      continue
    fi
    result_line="$(grep -F -- "$token" "$work/$model.results")"
    grep -nF -- "$token" "$work/$model.results" | cut -d: -f1 >> "$work/$model.claimed"
    if grep -qE ' is true\.?$' <<<"$result_line"; then
      got=true
    elif grep -qE ' is false\.?$' <<<"$result_line"; then
      got=false
    else
      got=unproved
    fi
    queries=$((queries + 1))
    if [ "$got" != "$want" ]; then
      fail "$model: '$token' is $got, expected $want ($result_line)"
    fi
  done < "$work/expected"
  total="$(wc -l < "$work/$model.results" | tr -d ' ')"
  claimed="$(sort -u "$work/$model.claimed" | wc -l | tr -d ' ')"
  if [ "$claimed" != "$total" ]; then
    fail "$model: $((total - claimed)) RESULT line(s) no expectation names"
    grep -nvF -f <(cut -d'|' -f2 "$work/expected") "$work/$model.results" >&2 || true
  fi
done < "$work/listed"

echo "pq-model: $queries queries in $models models checked against $(basename "$EXPECTED")"
finish pq-model
