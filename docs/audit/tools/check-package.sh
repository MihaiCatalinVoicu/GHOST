#!/usr/bin/env bash
# GHOST audit package: consistency check. Exits non-zero if a number, a recipe or a handling rule of the
# package in docs/audit/ no longer matches the tree. Written after two adversarial reviews of the package
# (2026-10-04) so that each defect they found fails here when it comes back:
#   * sizes: the numbers in the documents equal the output of tools/measure.sh (test-only code excluded);
#   * Appendix A of AUDIT_SCOPE.md is byte-identical to tools/measure.sh;
#   * the bundle and snapshot recipes of BUILD_AND_REVIEW_GUIDE.md section 1.2 run end to end;
#   * every CI run id the documents cite is in ci-runs.tsv;
#   * the sendable RFQ text contains no unfixed weakness, no pointer to the package or the owner's notes,
#     and no statement about where CI runs;
#   * the crate versions the documents name are the ones in Cargo.lock.
# Usage: bash docs/audit/tools/check-package.sh [--skip-measure]    (from anywhere inside the checkout)
# Needs git, bash, GNU awk, GNU sed, GNU xargs, tar, sha256sum. --skip-measure skips the 1-minute size run.
set -u
export LC_ALL=C
cd "$(git rev-parse --show-toplevel)"
A=docs/audit
fail=0
n_ok=0
ok()  { n_ok=$((n_ok + 1)); [ "${VERBOSE:-}" = 1 ] && echo "check ok: $*"; return 0; }
bad() { echo "CHECK FAIL: $*" >&2; fail=1; }
thousands() { printf '%s' "$1" | sed -E ':a;s/([0-9])([0-9]{3})($|,)/\1,\2\3/;ta'; }
expect() { # file, fixed string
  if grep -qF -- "$2" "$A/$1"; then ok "$1 has '$2'"; else bad "$1 does not contain '$2'"; fi
}
expect_not() { # file, fixed string
  if grep -qF -- "$2" "$A/$1"; then bad "$1 contains '$2'"; else ok "$1 has no '$2'"; fi
}
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

# ---- 1. the files of the package exist
for f in README.md README-RO.md AUDIT_SCOPE.md EVIDENCE_INDEX.md KNOWN_ISSUES.md BUILD_AND_REVIEW_GUIDE.md AUDITOR_RFQ.md \
         OWNER_ONLY_MARKET_AND_BUDGET.md ci-runs.tsv ci-log-facts.tsv tools/measure.sh tools/check-package.sh; do
  [ -f "$A/$f" ] && ok "$f exists" || bad "$A/$f is missing"
done
git cat-file -e a0f3f58ef76bfd4e45f73fd0f1eaf9a89d5750e5 2>/dev/null && ok "base commit a0f3f58 is in this repository" \
  || bad "the base commit a0f3f58ef76bfd4e45f73fd0f1eaf9a89d5750e5 is not in this repository (expected in a clone that lacks the history, e.g. made from a snapshot; every other check still ran)"

# ---- 2. Appendix A is the measurement script
awk '/^## Appendix A/ {on=1} on && /^```bash$/ {inb=1; next} inb && /^```$/ {exit} inb {print}' "$A/AUDIT_SCOPE.md" > "$T/appendix.sh"
if diff -q "$T/appendix.sh" "$A/tools/measure.sh" >/dev/null; then ok "Appendix A equals tools/measure.sh"; else bad "Appendix A of AUDIT_SCOPE.md differs from tools/measure.sh"; fi

# ---- 3. the sizes and counts in the documents are the measured ones
if [ "${1:-}" != "--skip-measure" ]; then
  bash "$A/tools/measure.sh" "$T" > "$T/measure.out" 2> "$T/measure.err" || bad "tools/measure.sh failed: $(head -c 300 "$T/measure.err")"
  kv() { sed -n "s/^$1=//p" "$T/measure.out" | head -1; }
  crate() { awk -F'\t' -v c="$1" '/^## rust crates/ {on=1; next} /^## totals/ {on=0} on && $1 == c {print $6}' "$T/measure.out"; }
  rprod=$(kv rust_prod_lines); rsrc=$(kv rust_src_lines); rtest=$(kv rust_testonly_lines)
  kmain=$(kv kotlin_main_lines); krel=$(kv kotlin_release_lines); kut=$(kv kotlin_unit_test_lines)
  rint=$(kv rust_integration_test_lines); koth=$(kv kotlin_otherset_lines)
  kprod=$((kmain + krel)); total=$((rprod + kprod))
  r2a=$(( $(crate issuer/api) + $(crate issuer/blind-rsa) + $(crate issuer/entitlement) ))
  [ -n "$rprod" ] && [ -n "$kmain" ] || bad "tools/measure.sh printed no totals"
  for pair in "AUDIT_SCOPE.md:$(thousands "$rprod")" "AUDIT_SCOPE.md:$(thousands "$rsrc")" "AUDIT_SCOPE.md:$(thousands "$rtest")" \
              "AUDIT_SCOPE.md:$(thousands "$kprod")" "AUDIT_SCOPE.md:$(thousands "$total")" "AUDIT_SCOPE.md:$(thousands "$kut")" \
              "AUDIT_SCOPE.md:$(thousands "$rint")" "AUDIT_SCOPE.md:$(thousands "$koth")" \
              "OWNER_ONLY_MARKET_AND_BUDGET.md:$(thousands "$total")" "OWNER_ONLY_MARKET_AND_BUDGET.md:$(thousands "$rtest")" \
              "OWNER_ONLY_MARKET_AND_BUDGET.md:$(thousands "$kut")" "OWNER_ONLY_MARKET_AND_BUDGET.md:$(thousands "$rint")"; do
    expect "${pair%%:*}" "${pair#*:}"
  done
  for c in relay issuer/service issuer/ops client-core/net client-core/dm; do
    expect AUDIT_SCOPE.md "$(thousands "$(crate $c)")"
  done
  expect AUDIT_SCOPE.md "$(thousands "$r2a")"
  expect AUDIT_SCOPE.md "$(kv rust_prod_files) source files"
  expect AUDIT_SCOPE.md "$(thousands "$(kv files_total)") files"
  expect AUDIT_SCOPE.md "$(thousands "$(kv phys_lines_total)") physical lines"
  expect AUDIT_SCOPE.md "$(kv rust_src_files) files"
  expect AUDIT_SCOPE.md "in $(( $(kv kotlin_main_files) + $(kv kotlin_release_files) )) files"
  expect AUDITOR_RFQ.md "$(thousands "$(crate client-core/dm)") Rust"
  expect OWNER_ONLY_MARKET_AND_BUDGET.md "$(thousands "$(crate client-core/dm)")"
  expect OWNER_ONLY_MARKET_AND_BUDGET.md "$(thousands "$(crate client-core/net)")"
  expect EVIDENCE_INDEX.md "**$(kv rust_test_attrs_total)** ($(kv rust_test_attrs_main) in the main workspace"
  expect EVIDENCE_INDEX.md "**$(thousands "$(kv kotlin_test_attrs_total)")**"
  expect AUDIT_SCOPE.md "$(kv rust_test_attrs_main) in the main workspace"
  # the ratio of test code to production code is stated as 1.8
  ratio=$(awk -v t="$((kut + rint + rtest))" -v p="$total" 'BEGIN {printf "%.1f", t / p}')
  [ "$ratio" = "1.8" ] && ok "test code is $ratio times the production code" || bad "test code is $ratio times the production code; the documents say 1.8"
  expect AUDIT_SCOPE.md "1.8 times"
fi

# ---- 4. every CI run id cited is in ci-runs.tsv
cited=$(cat "$A"/*.md | grep -o -E '\b3[0-9]{10}\b' | sort -u)
missing=""
for id in $cited; do grep -q "^$id	" "$A/ci-runs.tsv" || missing="$missing $id"; done
[ -z "$missing" ] && ok "every cited run id is in ci-runs.tsv" || bad "run ids cited but not in ci-runs.tsv:$missing"

# ---- 5. the RFQ is sendable: nothing below its owner block that must not reach a bidder before the NDA
awk '/^## B0\. Cover/ {on=1} on' "$A/AUDITOR_RFQ.md" > "$T/rfq-sendable.md"
[ -s "$T/rfq-sendable.md" ] || bad "AUDITOR_RFQ.md has no 'B0. Cover' heading"
for w in 'MD-1' 'CRY-P9' 'own machines' 'owner'"'"'s own' 'self-hosted' 'AUDIT_SCOPE' 'KNOWN_ISSUES' 'EVIDENCE_INDEX' 'BUILD_AND_REVIEW' 'OWNER_ONLY' 'README-RO' 'Part A' 'Symbolic' 'Cure53' 'Trail of Bits' 'Least Authority'; do
  if grep -qF -- "$w" "$T/rfq-sendable.md"; then bad "the sendable RFQ text contains '$w'"; else ok "the sendable RFQ text has no '$w'"; fi
done
grep -qE '10-14 weeks|six to eight auditors' "$T/rfq-sendable.md" && bad "the RFQ gives a sizing while saying it does not disclose one" || ok "the RFQ gives no sizing"
grep -qF 'NDA' "$T/rfq-sendable.md" && grep -qF 'Known issues.' "$T/rfq-sendable.md" && ok "the RFQ has the NDA step and the known-issues rule" || bad "the RFQ lacks the NDA step or the known-issues rule"
# nothing sendable in the auditor documents may point at the owner-only file except the two places that say it stays home
for f in EVIDENCE_INDEX.md KNOWN_ISSUES.md BUILD_AND_REVIEW_GUIDE.md; do expect_not "$f" 'OWNER_ONLY'; done

# ---- 6. the hand-over recipes of BUILD_AND_REVIEW_GUIDE.md section 1.2 run end to end
G="$A/BUILD_AND_REVIEW_GUIDE.md"
want='sha256sum -c ghost-audit-rc1.bundle.sha256 && git clone ghost-audit-rc1.bundle ghost && cd ghost && git bundle verify ../ghost-audit-rc1.bundle && git checkout audit-rc1 && git rev-parse HEAD'
grep -qF -- "$want" "$G" && ok "the guide has the auditor-side bundle sequence" || bad "the guide does not contain the corrected auditor-side bundle sequence"
grep -qF -- 'git archive --format=tar.gz --prefix=ghost-audit-rc1/ audit-rc1 ghost docs output .github .gitattributes .gitignore LICENSE README.md' "$G" \
  && ok "the guide's snapshot command keeps the dot files" || bad "the guide's snapshot command drops .gitattributes and .gitignore"
(
  set -e
  cd "$T" && mkdir owner auditor && cd owner && git init -q . && git config user.email check@example.invalid && git config user.name check && git config core.autocrlf false && git config core.safecrlf false
  mkdir ghost docs output .github && echo a > ghost/a.txt && echo b > docs/b.txt && echo c > output/c.txt && echo d > .github/d.txt \
    && echo e > LICENSE && echo f > README.md && echo '* text=auto' > .gitattributes && echo target > .gitignore
  git add -A && git commit -q -m one && c=$(git rev-parse HEAD)
  git tag -a audit-rc1 -m "GHOST audit snapshot" "$c"
  git bundle create ../auditor/ghost-audit-rc1.bundle audit-rc1 >/dev/null 2>&1
  (cd ../auditor && sha256sum ghost-audit-rc1.bundle > ghost-audit-rc1.bundle.sha256)
  git archive --format=tar.gz --prefix=ghost-audit-rc1/ audit-rc1 ghost docs output .github .gitattributes .gitignore LICENSE README.md > ../snap.tar.gz
  tar tzf ../snap.tar.gz | grep -qx 'ghost-audit-rc1/.gitattributes'
  tar tzf ../snap.tar.gz | grep -qx 'ghost-audit-rc1/.gitignore'
  cd ../auditor
  # the sequence as it used to be written (verify first) stops outside a repository: that was the defect the review found
  if (git bundle verify ghost-audit-rc1.bundle >/dev/null 2>&1); then echo "note: this git verifies a bundle outside a repository; the corrected sequence is still the one to use" >&2; fi
  got=$(bash -c "$want" 2>/dev/null | tail -1)
  [ "$got" = "$c" ]
) && ok "bundle and snapshot recipes run end to end" || bad "the bundle or snapshot recipe of the guide does not run end to end"

# ---- 7. versions the documents name are the ones in Cargo.lock
lock=ghost/Cargo.lock
for nv in "vodozemac 0.11.0" "matrix-pickle 0.2.3" "libcrux-kem 0.0.9" "libcrux-ml-kem 0.0.10" "blind-rsa-signatures 0.17.2" \
          "rsa 0.10.0-rc.18" "rsa 0.9.10" "ring 0.17.14" "arti-client 0.46.0" "tonic 0.14.6" "redb 4.2.0" "jni 0.21.1" \
          "ed25519-dalek 2.2.0" "x25519-dalek 2.0.1" "chacha20poly1305 0.11.0" "hkdf 0.13.0" "num-bigint-dig 0.8.6"; do
  name=${nv% *}; ver=${nv#* }
  if awk -v n="$name" -v v="$ver" '$0 == "name = \"" n "\"" {getline l; if (l == "version = \"" v "\"") f=1} END {exit !f}' "$lock"; then
    ok "Cargo.lock has $nv"
  else bad "Cargo.lock has no $nv"; fi
  grep -qF -- "$name $ver" "$A/AUDIT_SCOPE.md" || grep -qF -- "$name\` $ver" "$A/AUDIT_SCOPE.md" || bad "AUDIT_SCOPE.md does not name $nv"
done

# ---- 8. every markdown table row has as many cells as its header (an unescaped '|' in a cell breaks a table)
for f in "$A"/*.md; do
  awk -v file="$f" '
    function cells(s,   t) { t = s; gsub(/\\\|/, "\001", t); return gsub(/\|/, "|", t) - 1 }
    /^```/ { fence = !fence; n = 0; next }
    fence { next }
    /^\|/ { c = cells($0); if (n == 0) hc = c; n++; if (c != hc) { printf "%s:%d: %d cells, header has %d\n", file, NR, c, hc; bad = 1 } next }
    { n = 0 }
    END { exit bad }' "$f" || bad "a table row of $f has a different number of cells than its header"
done
[ "$fail" = 0 ] && ok "all markdown tables are well formed"

if [ "$fail" = 0 ]; then echo "[check-package] OK ($n_ok checks)"; else echo "[check-package] FAILED" >&2; exit 1; fi
