#!/usr/bin/env bash
# Gate G-D9 (Phase 14 design faza14-distribution.md row G-D9, D25, ADR-39 points 4 and 6):
# nothing published — a release output, the public repository's tree, archive texts — may
# carry the owner's personal identifiers. The patterns live in identity-patterns.txt (one
# literal per line, ASCII case-insensitive; export-public sweeps the public tree against
# the same list at export time).
#
#   public-identity-scrub.sh <dir>       every regular file under <dir> (binary-safe) must
#                                        carry no pattern; the release recipe (build-release.sh
#                                        step 7) runs this over the whole output, after the
#                                        notices and SBOMs exist and before SHA256SUMS.
#   public-identity-scrub.sh --committed the committed files the design names today:
#                                        licenses/apk-notices-preamble.txt (the APK asset's
#                                        first page) and ghost/Cargo.toml's repository field
#                                        (cargo metadata carries it into an SBOM). Both name
#                                        the owner today by the design's own note (D25; the
#                                        S3 slice replaces them with the provisional project
#                                        identity), so this mode is expected to fail until
#                                        then — it exists so static-gates can adopt it the
#                                        day the names change.
#
# A hit is reported as `path: pattern` and fails the gate; scans are byte-based, so
# compressed or encoded carriers a plain grep would miss still match only when the pattern
# is literal — which is what the design's list is.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
PATTERNS="$GATES_DIR/identity-patterns.txt"
[ -f "$PATTERNS" ] || { echo "identity-patterns.txt missing" >&2; exit 2; }
mapfile -t PATTERNS_LIST < <(grep -vE '^\s*(#|$)' "$PATTERNS")

scrub_file() { # $1 = file (reports one failure line per hit)
  # Case-insensitivity without grep -i: this toolchain's grep aborts on -i, and tr keeps the
  # pipeline pipefail-safe through process substitution.
  local f="$1" p n=0
  for p in "${PATTERNS_LIST[@]}"; do
    n=$((n + 1))
    if grep -qF -- "${p,,}" < <(tr 'A-Z' 'a-z' < "$f" 2>/dev/null); then
      fail "${f}: identity pattern #${n} ($(printf '%.40s' "$p")…)"
    fi
  done
}

mode="${1:-}"
[ -n "$mode" ] || { echo "usage: public-identity-scrub.sh <dir> | --committed" >&2; exit 2; }

if [ "$mode" = "--committed" ]; then
  scrub_file "$GHOST_ROOT/licenses/apk-notices-preamble.txt"
  if grep -qE '^repository *= *"[^"]*(mihai|mihayyy|github\.com/mihai)' \
      < <(tr 'A-Z' 'a-z' < "$GHOST_ROOT/Cargo.toml" 2>/dev/null); then
    fail "Cargo.toml: the repository field names the personal account (D25; the S3 project identity replaces it)"
  fi
  finish public-identity-scrub
fi

[ -d "$mode" ] || { echo "public-identity-scrub: $mode is not a directory" >&2; exit 2; }
while IFS= read -r f; do
  scrub_file "$f"
done < <(find "$mode" -type f -print 2>/dev/null | sort)
finish public-identity-scrub
