#!/usr/bin/env bash
# GHOST audit package: size and test-count measurement (AUDIT_SCOPE.md section 2 and Appendix A).
# Run from anywhere inside a clean checkout. Usage: measure.sh [scratch dir, default /tmp]
# Needs git, bash, GNU awk and GNU xargs (-d). Nothing is built; only tracked files are read.
set -u
cd "$(git rev-parse --show-toplevel)"; T="${1:-/tmp}"
EXT='\.(rs|kt|kts|java|proto|sh|pl|pv|yml|yaml|toml|xml|sql|json|patch|ps1|bat|pro|properties)$'
git ls-files ghost .github | grep -E "$EXT" > "$T/files.txt"
xargs -d '\n' wc -l < "$T/files.txt" | grep -v ' total$' | awk '{n=$1; $1=""; sub(/^ /,""); print n "\t" $0}' > "$T/phys.tsv"
xargs -d '\n' grep -c -v '^[[:space:]]*$' < "$T/files.txt" | awk -F: '{print $NF "\t" substr($0,1,length($0)-length($NF)-1)}' > "$T/nb.tsv"

echo "## components: component, language, kind, files, physical lines, non-blank lines"
awk -F'\t' 'FNR==NR{nb[$2]=$1;next}{p=$2;n=$1;b=nb[p];
  comp="other"; if(p~/^ghost\/relay\//)comp="relay"; else if(p~/^ghost\/issuer\/crates\/[a-z-]+\//){split(p,a,"/");comp="issuer/" a[4]}
  else if(p~/^ghost\/client-core\/[a-z-]+\//){split(p,a,"/");comp="client-core/" a[3]}
  else if(p~/^ghost\/android\/[a-z-]+\//){split(p,a,"/");comp="android/" a[3]}
  else if(p~/^ghost\/(protocol|scripts|infra|licenses|test-harness)\//){split(p,a,"/");comp=a[2]} else if(p~/^\.github\//)comp="ci";
  lang=(p~/\.rs$/)?"Rust":(p~/\.kt$/)?"Kotlin":(p~/\.kts$/)?"Gradle":(p~/\.sh$/)?"Shell":(p~/\.pl$/)?"Perl":"misc";
  kind="all"; if(lang=="Rust"){kind=(p~/\/tests\//)?"tests":(p~/\/(examples|fuzz|benches)\//)?"aux":"src"}
  else if(lang=="Kotlin"){kind=(p~/\/src\/main\//)?"main":(p~/\/src\/release\//)?"release":(p~/\/src\/test\//)?"test":"otherset"}
  k=comp"\t"lang"\t"kind; f[k]++; ph[k]+=n; nbl[k]+=b}
  END{for(k in f)print k"\t"f[k]"\t"ph[k]"\t"nbl[k]}' "$T/nb.tsv" "$T/phys.tsv" | sort > "$T/components.tsv"
cat "$T/components.tsv"

# Rust `src/` files: lines inside test-only items. Test-only = #[cfg(test)], feature "test-vectors",
# any(test, feature "pq-spy") and feature "clippy-fixture" (test and fixture features that no shipped
# build enables). An item runs from its attribute line to its closing brace at the same indentation
# (rustfmt layout, enforced by `cargo fmt --check`) or to its terminating ';'. A `mod x;` declared
# that way makes the whole file x.rs test-only. Small gated statements and functions count as well.
cat > "$T/testonly.awk" <<'AWK'
function ind_of(s) { match(s, /^ */); return RLENGTH }
function is_test_attr(s) {
  return (s ~ /^[ \t]*#\[cfg\((test|feature = "test-vectors"|any\(test, feature = "pq-spy"\)|feature = "clippy-fixture")\)\][ \t]*$/)
}
function flush(   i, j, k, m, ind, cnt, kids, name, dir, base, pre, b) {
  if (cur == "") return
  dir = cur; sub(/[^\/]*$/, "", dir); base = cur; sub(/^.*\//, "", base)
  if (base == "lib.rs" || base == "main.rs" || base == "mod.rs") pre = dir
  else { b = base; sub(/\.rs$/, "", b); pre = dir b "/" }
  cnt = 0; kids = ""; i = 1
  while (i <= n) {
    if (!is_test_attr(L[i])) { i++; continue }
    ind = ind_of(L[i]); j = i + 1
    while (j <= n && (L[j] ~ /^[ \t]*#\[/ || L[j] ~ /^[ \t]*\/\/\//)) j++
    if (L[j] ~ /^[ \t]*(pub(\([a-z]+\))?[ \t]+)?mod[ \t]+[A-Za-z0-9_]+[ \t]*;/) {
      name = L[j]; sub(/^[ \t]*(pub(\([a-z]+\))?[ \t]+)?mod[ \t]+/, "", name); sub(/[ \t]*;.*$/, "", name)
      kids = kids " " pre name ".rs " pre name "/mod.rs"; cnt += j - i + 1; i = j + 1; continue
    }
    k = j
    while (k <= n && L[k] !~ /[{;][ \t]*(\/\/.*)?$/) k++
    if (k > n) { i = j; continue }
    if (L[k] ~ /;[ \t]*(\/\/.*)?$/) { cnt += k - i + 1; i = k + 1; continue }
    m = k + 1
    while (m <= n && !(substr(L[m], 1, ind) == substr(SP, 1, ind) && substr(L[m], ind + 1, 1) == "}")) m++
    if (m > n) m = n
    cnt += m - i + 1; i = m + 1
  }
  print cur "\t" n "\t" cnt "\t" kids
}
BEGIN { SP = sprintf("%80s", "") }
FNR == 1 { flush(); cur = FILENAME; n = 0; delete L }
{ n++; L[n] = $0 }
END { flush() }
AWK
git ls-files ghost | grep '\.rs$' | grep -vE '/(tests|examples|fuzz|benches)/|test-harness/gates/' > "$T/rs.txt"
xargs -d '\n' awk -f "$T/testonly.awk" < "$T/rs.txt" > "$T/rs-split.tsv"
awk -F'\t' '
{ f[NR]=$1; n[$1]=$2; c[$1]=$3; if ($4 != "") { m = split($4, a, " "); for (x = 1; x <= m; x++) kid[a[x]] = 1 } }
END {
  for (i = 1; i <= NR; i++) { p = f[i]; split(p, a, "/");
    k = a[2]; if (a[2]=="client-core"||a[2]=="test-harness") k = a[2] "/" a[3]; else if (a[2]=="issuer") k = "issuer/" a[4];
    t = (p in kid) ? n[p] : c[p];
    SRC[k] += n[p]; TST[k] += t; if (!(p in kid)) FP[k]++; FA[k]++ }
  for (k in SRC) printf "%s\t%d\t%d\t%d\t%d\t%d\n", k, FA[k], FP[k], SRC[k], TST[k], SRC[k]-TST[k]
}' "$T/rs-split.tsv" | sort > "$T/rs-crates.tsv"
echo "## rust crates: crate, src files, files not wholly test-only, src lines, test-only lines, production lines"
cat "$T/rs-crates.tsv"

echo "## totals (key=value)"
echo "files_total=$(wc -l < "$T/files.txt" | tr -d ' ')"
awk '{s += $1} END {print "phys_lines_total=" s}' "$T/phys.tsv"
# Shipped or deployed Rust = relay, issuer/*, client-core/net, client-core/dm. dm-host (a test-only
# cdylib), test-harness and the separate mls-spike workspace are not shipped and are left out.
awk -F'\t' '$1 ~ /^(relay|issuer\/.*|client-core\/net|client-core\/dm)$/ {fa+=$2; fp+=$3; s+=$4; t+=$5; p+=$6}
  END {printf "rust_src_files=%d\nrust_prod_files=%d\nrust_src_lines=%d\nrust_testonly_lines=%d\nrust_prod_lines=%d\n", fa, fp, s, t, p}' "$T/rs-crates.tsv"
awk -F'\t' '$1 ~ /^android\// && $2 == "Kotlin" {s[$3] += $5; fl[$3] += $4}
  END {printf "kotlin_main_lines=%d\nkotlin_main_files=%d\nkotlin_release_lines=%d\nkotlin_release_files=%d\nkotlin_unit_test_lines=%d\nkotlin_unit_test_files=%d\nkotlin_otherset_lines=%d\n",
       s["main"], fl["main"], s["release"], fl["release"], s["test"], fl["test"], s["otherset"]}' "$T/components.tsv"
awk -F'\t' '$2 == "Rust" && $3 == "tests" && $1 ~ /^(relay|issuer\/.*|client-core\/net|client-core\/dm)$/ {s+=$5; fl+=$4}
  END {printf "rust_integration_test_lines=%d\nrust_integration_test_files=%d\n", s, fl}' "$T/components.tsv"

echo "## static test counts (key=value)"
git ls-files '*.rs' | grep -v test-harness/gates | xargs -d '\n' grep -c -E '^\s*#\[(test|tokio::test)' | awk -F: '
  { w = ($1 ~ /mls-spike/) ? "mls_spike" : ($1 ~ /client-core\/dm\/fuzz\//) ? "dm_fuzz" : "main"; s[w] += $2; t += $2 }
  END { printf "rust_test_attrs_main=%d\nrust_test_attrs_dm_fuzz=%d\nrust_test_attrs_mls_spike=%d\nrust_test_attrs_total=%d\n", s["main"], s["dm_fuzz"], s["mls_spike"], t }'
git ls-files 'ghost/android/*.kt' | xargs -d '\n' grep -c '@Test' | awk -F: '
  { w = ($1 ~ /\/src\/test\//) ? "unit" : ($1 ~ /\/src\/androidTest\//) ? "android_test" : "other"; s[w] += $2; t += $2 }
  END { printf "kotlin_test_attrs_unit=%d\nkotlin_test_attrs_android_test=%d\nkotlin_test_attrs_total=%d\n", s["unit"], s["android_test"], t }'
echo "## end"
