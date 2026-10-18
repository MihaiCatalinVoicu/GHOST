#!/usr/bin/env bash
# Gate G-U8 (Phase 13 design faza13-ux.md §8.5; invariant T56, ADR-56): the claims register is
# the only place an effect sentence lives.
#
#   rule 1 (triggers): every :ui string resource whose Romanian or English text matches
#     claims-triggers.tsv is a CLAIM row in claims.tsv (with evidence), or a reviewed line in
#     claims-allow.tsv — whatever its author called it
#   rule 3 (release): a limit_/goal_/claim_ resource has a register row of that kind; a CLAIM
#     whose evidence is not entirely green appears in no release source set's strings.xml
#   rule 4 (green list): every claims-evidence.txt line's hash matches the archived report
#   rule 6 (forbidden phrases): §8.4's words appear nowhere in :ui resources outside
#     claims-allow.tsv
#
# Coverage (rule 2) binds when the disclosure screens land (S2 onward); the register file exists
# from S0b so the gate's floor is real.

set -euo pipefail
GATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$GATES_DIR/../.." && pwd)}"
FAILURES=0
fail() { echo "GATE-FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }

CLAIMS="$GHOST_ROOT/android/ui/claims/claims.tsv"
TRIGGERS="$GHOST_ROOT/android/ui/claims/claims-triggers.tsv"
ALLOW="$GHOST_ROOT/android/ui/claims/claims-allow.tsv"
GREEN="$GHOST_ROOT/test-harness/privacy/claims-evidence.txt"

[ -f "$CLAIMS" ] || fail "claims.tsv missing"
[ -f "$TRIGGERS" ] || fail "claims-triggers.tsv missing"
[ -f "$ALLOW" ] || fail "claims-allow.tsv missing"
[ -f "$GREEN" ] || fail "claims-evidence.txt missing"

# Green evidence IDs (column 1), for rule 1's "with evidence" and rule 3's release rule.
green_ids() { [ -f "$GREEN" ] && awk '!/^#/ && NF {print $1}' "$GREEN" || true; }

# Collect the register rows: id -> kind,evidence
declare -A KIND=() EVID=()
while IFS=$'\t' read -r id kind evid residue source extra; do
  case "$id" in ''|\#*) continue ;; esac
  KIND[$id]="$kind"
  EVID[$id]="$evid"
  case "$kind" in LIMIT|FEATURE|GOAL|CLAIM) ;;
    *) fail "claims.tsv: '$id' has kind '$kind' (LIMIT|FEATURE|GOAL|CLAIM)" ;;
  esac
done < "$CLAIMS"

# Rule 1: triggers over every :ui values*/strings.xml.
trigger_re=$(grep -vE '^\s*(#|$)' "$TRIGGERS" | sed 's/[.[\*^$()+?{}|]/\\&/g' | paste -sd'|' - || true)
allowed_ids=$(grep -vE '^\s*(#|$)' "$ALLOW" | cut -f1 | tr '\n' ' ' || true)
while IFS= read -r sf; do
  rel="${sf#"$GHOST_ROOT"/}"
  while IFS= read -r row; do
    [ -n "$row" ] || continue
    sid=$(printf '%s' "$row" | cut -d'"' -f2)
    text=$(printf '%s' "$row" | sed -E 's/^[^>]*>//;s/<\/string>.*$//' | tr 'A-Z' 'a-z')
    [ -n "$trigger_re" ] || continue
    if printf '%s' "$text" | grep -qiE "$trigger_re"; then
      case " $allowed_ids " in
        *" $sid "*) continue ;;
      esac
      k="${KIND[$sid]:-}"
      if [ "$k" != "CLAIM" ]; then
        fail "$rel: '$sid' matches an effect trigger but is not a CLAIM row (kind: '${k:-none}')"
      elif [ "${EVID[$sid]:-}" = "-" ]; then
        fail "$rel: '$sid' is a CLAIM without evidence"
      fi
    fi
  done < <(grep -oE '<string name="[^"]+">[^<]*</string>' "$sf" || true)
done < <(find "$GHOST_ROOT/android/ui/src" -path '*/res/values*/strings.xml' 2>/dev/null || true)

# Rule 3: limit_/goal_/claim_ resources carry a row of that kind.
while IFS= read -r sf; do
  rel="${sf#"$GHOST_ROOT"/}"
  release=0
  case "$rel" in */src/release/*) release=1 ;; esac
  for sid in $(grep -oE '<(string|plurals) name="(limit_|goal_|claim_)[^"]+"' "$sf" | sed -E 's/.*name="//;s/"//' | sort -u); do
    want=$(printf '%s' "$sid" | sed -E 's/^(limit_|goal_|claim_).*/\1/' | tr 'a-z' 'A-Z' | sed 's/LIMIT_/LIMIT/;s/GOAL_/GOAL/;s/CLAIM_/CLAIM/')
    got="${KIND[$sid]:-}"
    [ "$got" = "$want" ] || fail "$rel: '$sid' is a $want string but its register row kind is '${got:-missing}'"
    # A CLAIM whose evidence is not entirely green appears in no release source set.
    if [ "$want" = "CLAIM" ] && [ "$release" = "1" ]; then
      ok=1
      for e in $(printf '%s' "${EVID[$sid]:-}" | tr ',' ' '); do
        [ "$e" = "-" ] && continue
        green_ids | grep -qx "$e" || ok=0
      done
      [ "$ok" = "1" ] || fail "$rel: '$sid' is a CLAIM with non-green evidence in a release source set (rule 3)"
    fi
  done
done < <(find "$GHOST_ROOT/android/ui/src" -path '*/res/values*/strings.xml' 2>/dev/null || true)

# Rule 4: the green list's hashes match the archived reports.
while IFS= read -r line; do
  case "$line" in ''|\#*) continue ;; esac
  set -- $line
  eid="$1"; run="$2"; commit="$3"; check="$4"; want_sha="$5"
  report="$GHOST_ROOT/docs/evidence/$eid-$run.txt"
  if [ ! -f "$report" ]; then
    fail "claims-evidence.txt: '$eid' has no archived report at docs/evidence/$eid-$run.txt"
  else
    got_sha=$(sha256sum "$report" | cut -d' ' -f1)
    [ "$got_sha" = "$want_sha" ] || fail "claims-evidence.txt: '$eid' hash mismatch (listed $want_sha, archived $got_sha)"
  fi
done < "$GREEN"

# Rule 6: forbidden phrases (§8.4) in :ui resources, outside claims-allow.tsv.
FORBIDDEN='100%|complet anonim|total privat|nimeni nu poate|imposibil de|anonimat garantat|untraceable|unbreakable|military-grade|open source|sursă deschisă|sursa deschisă|verificabil de oricine|quantum-proof|rezistent cuantic|criptare end-to-end post-cuantică|ratchet PQ|protocolul Signal|verificat formal|military grade'
while IFS= read -r sf; do
  rel="${sf#"$GHOST_ROOT"/}"
  hits=$(grep -inE "$FORBIDDEN" "$sf" || true)
  [ -z "$hits" ] || while IFS= read -r h; do fail "$rel: forbidden phrase: $h"; done <<< "$hits"
done < <(find "$GHOST_ROOT/android/ui/src" -path '*/res/values*/strings.xml' 2>/dev/null || true)

if [ "$FAILURES" -gt 0 ]; then echo "[ui-claims] FAILED with $FAILURES violation(s)" >&2; exit 1; fi
echo "[ui-claims] OK"
