#!/usr/bin/env bash
# Gate G-U11 (Phase 13 design faza13-ux.md §13.1, §3.4; invariants T15m, T16, T54): the merged
# release manifest carries exactly one exported component — the launcher activity — and the link
# surface leaves no trace in the OS.
#
#   exactly one <activity> in the merged manifest, exported, launchMode="singleTask",
#     persistableMode="persistNever"
#   its VIEW intent filters declare scheme "ghost" with hosts invite, contact and channel only
#   no http(s) data in any intent filter, no android:autoVerify
#   no permission outside T15 (Phase 14's REQUEST_INSTALL_PACKAGES lands with ADR-51 and the
#     store flavor must then lack it)
#   android.hardware.camera not required
#
# Like merged-manifest-lint.sh this gate needs the build: CI runs it in the android job. It reads
# the merged RELEASE manifest of :app (the mirror and store flavors join the set when Phase 14
# adds them; the debug/gate build types are gate-test variants, not release manifests).
#
# Usage: ui-manifest.sh [merged AndroidManifest.xml ...]. Default: the release merged manifest
# under android/app/build/intermediates/merged_manifest/release.

set -euo pipefail
GATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$GATES_DIR/../.." && pwd)}"
FAILURES=0
fail() { echo "GATE-FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }

MANIFESTS=("$@")
if [ "${#MANIFESTS[@]}" -eq 0 ]; then
  while IFS= read -r m; do MANIFESTS+=("$m"); done < <(find "$GHOST_ROOT/android/app/build/intermediates/merged_manifest/release" -maxdepth 2 -name AndroidManifest.xml 2>/dev/null | sort || true)
fi
if [ "${#MANIFESTS[@]}" -eq 0 ]; then
  fail "no merged release manifest found (run :app:assembleRelease first; not run is red)"
fi

T15_RE='android\.permission\.(INTERNET|FOREGROUND_SERVICE|FOREGROUND_SERVICE_DATA_SYNC|POST_NOTIFICATIONS|CAMERA|USE_BIOMETRIC|VIBRATE|RECEIVE_BOOT_COMPLETED|ACCESS_NETWORK_STATE)|\.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'

for m in "${MANIFESTS[@]}"; do
  M_OUT="$(perl -e '
    my $t = do { local $/; open my $fh, "<", $ARGV[0] or die "cannot read $ARGV[0]"; <$fh> };
    my $n_act = () = $t =~ /<activity\b/g;
    print "ACTIVITIES\t$n_act\n";
    if ($t =~ /<activity\b([^>]*)>(.*?)<\/activity>/s) {
      my ($attrs, $body) = ($1, $2);
      for my $a (qw(android:name android:exported android:launchMode android:persistableMode)) {
        if ($attrs =~ /\Q$a\E="([^"]*)"/) { print "ACTATTR\t$a\t$1\n"; } else { print "ACTATTR\t$a\t(absent)\n"; }
      }
      my %hosts;
      while ($body =~ /<data[^>]*android:host="([^"]+)"/g) { $hosts{$1} = 1; }
      print "HOSTS\t" . join(" ", sort keys %hosts) . "\n";
      my $http = () = $body =~ /android:scheme="https?"/g;
      print "HTTPDATA\t$http\n";
    }
    my $autoverify = () = $t =~ /android:autoVerify="true"/g;
    print "AUTOVERIFY\t$autoverify\n";
    my %perms;
    while ($t =~ /android:name="(android\.permission\.[^"]+)"/g) { $perms{$1} = 1; }
    print "PERMS\t" . join(" ", sort keys %perms) . "\n";
    my $n_exported = () = $t =~ /android:exported="true"/g;
    print "EXPORTED\t$n_exported\n";
    if ($t =~ /<uses-feature[^>]*android:name="android\.hardware\.camera"[^>]*>/) {
      my $tag = $&;
      if ($tag =~ /android:required="([^"]+)"/) { print "CAMERA\t$1\n"; } else { print "CAMERA\t(absent)\n"; }
    } else { print "CAMERA\tnot-declared\n"; }
  ' "$m")"
  getf() { printf '%s\n' "$M_OUT" | grep "^$1" | head -1 | cut -f"$2"-; }
  n_activities=$(getf ACTIVITIES 2)
  [ "$n_activities" = "1" ] || fail "$m: exactly one activity expected, found '$n_activities'"
  if [ "$n_activities" = "1" ]; then
    exp=$(printf '%s\n' "$M_OUT" | grep $'^ACTATTR\tandroid:exported' | cut -f3)
    [ "$exp" = "true" ] || fail "$m: the activity is not exported (exported='$exp')"
    lm=$(printf '%s\n' "$M_OUT" | grep $'^ACTATTR\tandroid:launchMode' | cut -f3)
    pm=$(printf '%s\n' "$M_OUT" | grep $'^ACTATTR\tandroid:persistableMode' | cut -f3)
    [ "$lm" = "singleTask" ] || fail "$m: launchMode is '$lm', not singleTask (§3.4 D7)"
    [ "$pm" = "persistNever" ] || fail "$m: persistableMode is '$pm', not persistNever (§3.4 D7)"
  fi
  hosts=$(getf HOSTS 2)
  case "$hosts" in
    *invite*|*contact*|*channel*) ;;
    *) fail "$m: no ghost:// host filter (invite, contact, channel) found (hosts: '$hosts')" ;;
  esac
  for bad in $(getf HTTPDATA 2); do
    [ "$bad" = "0" ] || fail "$m: an http(s) data entry ships in a filter"
  done
  [ "$(getf AUTOVERIFY 2)" = "0" ] || fail "$m: autoVerify is banned (§3.4)"
  for p in $(getf PERMS 2); do
    printf '%s' "$p" | grep -qE "$T15_RE" || fail "$m: permission outside T15: $p"
  done
  cam=$(getf CAMERA 2)
  [ "$cam" = "not-declared" ] || [ "$cam" = "false" ] || fail "$m: the camera is required (§4.7): $cam"
  [ "$(getf EXPORTED 2)" = "1" ] || fail "$m: exactly one exported component expected, found $(getf EXPORTED 2)"
done

if [ "$FAILURES" -gt 0 ]; then echo "[ui-manifest] FAILED with $FAILURES violation(s)" >&2; exit 1; fi
echo "[ui-manifest] OK"
