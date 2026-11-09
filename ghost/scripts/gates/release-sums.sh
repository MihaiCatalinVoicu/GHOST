#!/usr/bin/env bash
# Gate G-D3 (Phase 14 design faza14-distribution.md §12.1; RK1 step 2's A/B equality):
#   release-sums.sh <dir-A> <dir-B>
# the two recipe-A outputs (the selfcheck layout has /out/A and /out/B) hold the SAME bytes.
#   1. The two SHA256SUMS are byte-equal, and each is complete over its own tree: every file
#      is listed, every listed file exists, and `sha256sum -c` passes (a hand-edited or
#      incomplete sums file fails).
#   2. The union of both trees holds no extra or missing file: the completeness check above
#      pins each tree to its sums, and the sums are equal — stated as its own message so a
#      drifted tree names the clause.
#   3. The APK's lib/<abi>/ entries equal the lib/ lines (§6.1's "what the APK contains"):
#      every lib/<abi>/libghost_client_net.so on disk hashes to the APK entry's bytes.
#   4. Each symbols/<abi>/*.debug build-id equals its library's (the split debug file
#      describes the shipped binary): the GNU build-id note is parsed from both ELF files
#      by hand (no binutils dependency; od only).
#
# This is a RELEASE-CEREMONY gate (it compares two build trees, not the repository): it is
# NOT in run-all.sh. The image selfchecks (selfcheck.sh, selfcheck-android.sh) exercise the
# same equality; this gate is the RK1 ceremony's explicit check over two finished outputs.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
A="${1:?usage: release-sums.sh <dir-A> <dir-B>}"
B="${2:?usage: release-sums.sh <dir-A> <dir-B>}"
for d in "$A" "$B"; do
  [ -d "$d" ] || { echo "release-sums: $d is not a directory" >&2; exit 2; }
  [ -f "$d/SHA256SUMS" ] || { echo "release-sums: $d/SHA256SUMS missing" >&2; exit 2; }
done
A="$(cd "$A" && pwd)"; B="$(cd "$B" && pwd)"

# 1+2: equal, complete sums.
if ! cmp -s "$A/SHA256SUMS" "$B/SHA256SUMS"; then
  diff "$A/SHA256SUMS" "$B/SHA256SUMS" | head -20 >&2 || true
  fail "the two SHA256SUMS differ (the trees are not byte-equal)"
fi
for d in "$A" "$B"; do
  check_log="$(mktemp)"
  if ! (cd "$d" && sha256sum -c SHA256SUMS >/dev/null 2>"$check_log" ); then
    cat "$check_log" >&2 || true
    rm -f "$check_log"
    fail "$d: SHA256SUMS does not verify over the tree"
  fi
  rm -f "$check_log"
  listed="$(tr -d '\r' < "$d/SHA256SUMS" | sed -E 's/^[0-9a-f]{64} +\*?(.*)$/\1/' | sort)"
  actual="$(cd "$d" && find . -type f ! -name SHA256SUMS -print | sed 's|^\./||' | sort)"
  [ "$listed" = "$actual" ] || fail "$d: SHA256SUMS is not complete over the tree (listed != actual files)"
done
echo "[release-sums] the two trees are byte-equal ($(wc -l < "$A/SHA256SUMS") files)"

# 3: the APK's native entries equal the lib/ lines.
apk="$(cd "$A" && ls apk/*-unsigned.apk 2>/dev/null | sed -n '1p')"
[ -n "$apk" ] || fail "$A: no unsigned APK under apk/ (the android half is not in this tree)"
for abi in arm64-v8a x86_64; do
  lib="$A/lib/$abi/libghost_client_net.so"
  [ -f "$lib" ] || fail "$A: $lib missing"
  entry="lib/$abi/libghost_client_net.so"
  if unzip -l "$A/$apk" | grep -q " $entry\$"; then
    in_apk="$(unzip -p "$A/$apk" "$entry" | sha256sum | cut -d' ' -f1)"
    on_disk="$(sha256sum "$lib" | cut -d' ' -f1)"
    [ "$in_apk" = "$on_disk" ] || fail "$entry: the APK carries $in_apk, lib/ holds $on_disk"
  else
    fail "$A/$apk: no $entry entry (the APK does not package the built library)"
  fi
done

# 4: build-id equality, parsed by hand (ELF64 LE, the .note.gnu.build-id section).
build_id() { # $1 = elf file; prints the id's hex or fails
  od -A n -t x1 -N 64 "$1" 2>/dev/null | tr -d ' \n' | grep -q '^7f454c460201' \
    || { echo "release-sums: $1 is not a 64-bit little-endian ELF" >&2; return 1; }
  local f="$1"
  shoff="$(od -A n -t u8 -j 40 -N 8 "$f" | tr -d ' ')"
  shentsize="$(od -A n -t u2 -j 58 -N 2 "$f" | tr -d ' ')"
  shnum="$(od -A n -t u2 -j 60 -N 2 "$f" | tr -d ' ')"
  shstrndx="$(od -A n -t u2 -j 62 -N 2 "$f" | tr -d ' ')"
  [ "$shentsize" -ge 64 ] 2>/dev/null || { echo "release-sums: $1 has no section table" >&2; return 1; }
  strtab_off="$(od -A n -t u8 -j $((shoff + shstrndx * shentsize + 24)) -N 8 "$f" | tr -d ' ')"
  i=0
  while [ "$i" -lt "$shnum" ]; do
    base=$((shoff + i * shentsize))
    name_hex="$(od -A n -t x1 -j $((strtab_off + $(od -A n -t u4 -j $((base)) -N 4 "$f" | tr -d ' '))) -N 20 "$f" | tr -d ' 
')"
    case "$name_hex" in
      2e6e6f74652e676e752e6275696c642d6964*)
        sec_off="$(od -A n -t u8 -j $((base + 24)) -N 8 "$f" | tr -d ' ')"
        descsz="$(od -A n -t u4 -j $((sec_off + 4)) -N 4 "$f" | tr -d ' ')"
        od -A n -t x1 -j $((sec_off + 16)) -N "$descsz" "$f" | tr -d ' 
'
        return 0 ;;
    esac
    i=$((i + 1))
  done
  echo "release-sums: $1 carries no .note.gnu.build-id" >&2
return 1
}
for abi in arm64-v8a x86_64; do
  lib="$A/lib/$abi/libghost_client_net.so"
  sym="$A/symbols/$abi/libghost_client_net.so.debug"
  [ -f "$sym" ] || fail "$A: $sym missing (the symbol split is part of the output)"
  id_lib="$(build_id "$lib")" || fail "$A: cannot read the build-id of $lib"
  id_sym="$(build_id "$sym")" || fail "$A: cannot read the build-id of $sym"
  [ "$id_lib" = "$id_sym" ] || fail "$abi: the symbol file's build-id ($id_sym) is not the library's ($id_lib)"
done

finish release-sums
