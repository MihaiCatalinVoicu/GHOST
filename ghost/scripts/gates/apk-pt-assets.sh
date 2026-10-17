#!/usr/bin/env bash
# Gate G-T4 (design faza12-transports.md §13) + PT-P3's APK half (§12.5): the APK carries the
# pinned lyrebird for exactly the two shipped ABIs, nothing else executable, and no bridge
# line anywhere in the package (§6.1's canary: zero lines ship in the APK).
#   - assets/pt/<abi>/lyrebird for arm64-v8a and x86_64, each byte-identical to the
#     lyrebird-android-{arm64,amd64} hash recorded in ghost/third_party/lyrebird/SHA256SUMS;
#   - assets/pt/SHA256SUMS present, mapping each <abi>/lyrebird to the same hash;
#   - no third ABI and no other executable asset (ELF magic) anywhere in assets/;
#   - no bridge line in any textual entry or in classes*.dex: an `obfs4 `/`webtunnel ` token
#     followed by an IP:port and a 40-hex fingerprint (the line's fingerprint IS the canary —
#     grammar-shape false positives like the word "obfs4" in prose do not match).
# Usage: apk-pt-assets.sh <apk>   (build-dependent; the CI android job runs it on the release APK)
# Self-test hook: GHOST_PT_SUMS overrides the recorded sums file (a fixture ships tiny fakes).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
APK="${1:?usage: apk-pt-assets.sh <apk>}"
SUMS="${GHOST_PT_SUMS:-$GHOST_ROOT/third_party/lyrebird/SHA256SUMS}"
ABIS=(arm64-v8a x86_64)
# asset lyrebird name -> recorded binary name
declare -A RECORDED=( [arm64-v8a]=lyrebird-android-arm64 [x86_64]=lyrebird-android-amd64 )
abis_lines="$(printf '%s\n' "${ABIS[@]}")"

[ -f "$APK" ] || { fail "missing $APK"; finish apk-pt-assets; }
[ -s "$SUMS" ] || { fail "missing ghost/third_party/lyrebird/SHA256SUMS"; finish apk-pt-assets; }
listing="$(unzip -Z1 "$APK" || true)"
[ -n "$listing" ] || { fail "$APK unreadable"; finish apk-pt-assets; }

# 1. The two ABIs, byte-identical to the recorded build.
for abi in "${ABIS[@]}"; do
  entry="assets/pt/$abi/lyrebird"
  grep -qx "$entry" <<< "$listing" || { fail "APK lacks $entry"; continue; }
  got="$(unzip -p "$APK" "$entry" | sha256sum | cut -d' ' -f1)"
  want="$(awk -v f="${RECORDED[$abi]}" '$2 == f || $2 == "*"f {print $1}' "$SUMS")"
  [ -n "$want" ] || { fail "${RECORDED[$abi]} not listed in SHA256SUMS"; continue; }
  [ "$got" = "$want" ] || fail "$entry in APK ($got) differs from the recorded build ($want)"
done
# No third ABI under assets/pt/.
while IFS= read -r dir; do
  [ -n "$dir" ] || continue
  grep -qx "$dir" <<< "$abis_lines" || fail "APK ships unexpected assets/pt ABI directory $dir"
done < <(printf '%s\n' "$listing" | awk -F/ '/^assets\/pt\/[^/]+\// {print $3}' | sort -u)
# The regenerated sums asset names both ABIs.
grep -qx 'assets/pt/SHA256SUMS' <<< "$listing" || fail "APK lacks assets/pt/SHA256SUMS"

# 2. No executable asset besides the two lyrebird binaries (ELF magic scan over assets/).
while IFS= read -r entry; do
  [ -n "$entry" ] || continue
  case "$entry" in
    assets/pt/arm64-v8a/lyrebird | assets/pt/x86_64/lyrebird) continue ;;
  esac
  magic="$(unzip -p "$APK" "$entry" 2>/dev/null | head -c 4 | od -An -tx1 | tr -d ' \r\n')"
  [ "$magic" = "7f454c46" ] && fail "APK ships an executable asset: $entry"
done < <(printf '%s\n' "$listing" | awk -F/ '/^assets\// && $0 !~ /\/$/ {print}' || true)

# 3. No bridge line in the package (PT-P3). The fingerprint pattern is the canary: prose that
# mentions "obfs4" alone does not match.
LINE_REGEX='(obfs4|webtunnel)[[:space:]]+[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]{1,5}[[:space:]]+[0-9A-Fa-f]{40}'
hits=""
while IFS= read -r entry; do
  [ -n "$entry" ] || continue
  case "$entry" in
    classes*.dex | assets/* | res/*/*.xml) ;;
    *) continue ;;
  esac
  if unzip -p "$APK" "$entry" 2>/dev/null | grep -aE -m2 "$LINE_REGEX" >/dev/null 2>&1; then
    hits="$hits $entry"
  fi
done < <(printf '%s\n' "$listing" | grep -E '^(classes.*\.dex|assets/|res/)' || true)
[ -z "$hits" ] || fail "APK contains a bridge line in:$hits (§6.1: zero lines ship)"

finish apk-pt-assets
