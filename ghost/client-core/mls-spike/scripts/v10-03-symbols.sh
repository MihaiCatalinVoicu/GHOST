#!/usr/bin/env bash
# V10-3: attributes the size difference between two unstripped builds of libghost_client_net.so
# (v10-03-size-build.sh ... --unstripped) to crates, per ABI: every defined symbol's size
# (llvm-nm -C -S --defined-only of NDK 30) summed by the first path segment of its demangled name.
# Approximate: generic instantiations land under `core`, `alloc` or the calling crate, and symbols
# without a Rust path (C code, anonymous constants) are summed as "(C or anonymous)".
# Evidence tooling, not product code (docs/design/faza10-s0-evidence.md §3).
#   v10-03-symbols.sh <baseline-unstripped-dir> <mls-unstripped-dir> [top N, default 25]
set -euo pipefail
BASE="${1:?usage: v10-03-symbols.sh <baseline-dir> <mls-dir> [N]}"
MLS="${2:?usage: v10-03-symbols.sh <baseline-dir> <mls-dir> [N]}"
TOP="${3:-25}"
NDK="${ANDROID_NDK_HOME:-${ANDROID_HOME:-$HOME/AppData/Local/Android/Sdk}/ndk/30.0.16248370}"
NM="$(ls "$NDK"/toolchains/llvm/prebuilt/*/bin/llvm-nm* 2>/dev/null | head -1)"
[ -x "$NM" ] || { echo "llvm-nm not found under $NDK" >&2; exit 2; }
by_crate() {
  "$NM" -C -S --defined-only "$1" | gawk '
    NF >= 4 {
      size = strtonum("0x" $2)
      name = $0; sub(/^[0-9a-f]+ +[0-9a-f]+ +[A-Za-z] +/, "", name)
      # Strip reference, pointer, qualifier and qualified-path prefixes: <&mut serde_json::… as …>
      do { old = name; sub(/^(<|&|\*|\(|\[|mut |const |dyn |impl |'"'"'[a-z_]+ )/, "", name) } while (name != old)
      if (name !~ /::/) { tot["(C or anonymous)"] += size; next }
      split(name, a, "::"); c = a[1]; sub(/[ <>(),].*/, "", c)
      if (c == "") c = "(C or anonymous)"
      tot[c] += size
    }
    END { for (k in tot) printf "%s\t%d\n", k, tot[k] }' | sort
}
for abi in arm64-v8a x86_64; do
  b="$BASE/$abi/libghost_client_net.so"; m="$MLS/$abi/libghost_client_net.so"
  join -t $'\t' -a 1 -a 2 -e 0 -o 0,1.2,2.2 <(by_crate "$b") <(by_crate "$m") |
    gawk -F'\t' -v abi="$abi" -v top="$TOP" '
      { d = $3 - $2; if (d != 0) { delta[$1] = d; net += d } }
      END {
        n = asorti(delta, keys, "@val_num_desc")
        printf "V10-3 symbols %s: net %+d B over the baseline (symbol sizes, not file size)\n", abi, net
        for (i = 1; i <= n && i <= top; i++) printf "V10-3 symbols %s %-32s %+9d B\n", abi, keys[i], delta[keys[i]]
      }'
done
