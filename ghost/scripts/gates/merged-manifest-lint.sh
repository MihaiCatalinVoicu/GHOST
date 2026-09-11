#!/usr/bin/env bash
# Gate T15m (Phase 7 design §5.5, §11.1 Q7, ADR-20): the MERGED release manifest of :app, i.e. what
# ships once the manifest merger has added every library's entries. manifest-lint.sh (T15) reads
# source manifests only. Checks:
#   - permissions: the T15 allowlist (common.sh), plus the app's own signature permission
#     <applicationId>.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION (androidx.core), the only permission
#     the app may declare; and the two the sync job needs are present: RECEIVE_BOOT_COMPLETED
#     (persisted job; JobSchedulerWake suppresses library lint's MissingPermission on this basis)
#     and ACCESS_NETWORK_STATE (network constraint), ADR-20;
#   - every exported component is the one LAUNCHER activity or is listed in MERGED_EXPORTED below
#     with its protecting permission and an ADR reference; a component with an intent filter must
#     declare android:exported explicitly;
#   - org.ghost.sync.android.SyncJobService is present, not exported and protected by
#     BIND_JOB_SERVICE (only the system binds it; ADR-20);
#   - the application keeps allowBackup="false", allows no cleartext traffic and is not debuggable.
# Usage: merged-manifest-lint.sh [merged AndroidManifest.xml ...]. Default: the :app release merged
# manifest under android/app/build/intermediates/merged_manifest/release (run :app:assembleRelease
# first). It needs the build, so CI runs it in the android job, not in run-all.sh. POSIX awk only
# (CI runners ship mawk).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
SYNC_JOB_SERVICE='org.ghost.sync.android.SyncJobService'
SYNC_JOB_PERMISSIONS='android.permission.RECEIVE_BOOT_COMPLETED|android.permission.ACCESS_NETWORK_STATE'
# Exported components besides the LAUNCHER activity, one "component|required permission|ADR" per
# entry. Empty: design §11.1 Q7 removed androidx.profileinstaller.ProfileInstallReceiver (exported,
# protected by DUMP) with tools:node="remove" in the app manifest.
MERGED_EXPORTED=()

# Reads the manifest as a stream of tags (RS="<"), skipping comments and declarations. Prints one
# line per violation, then T15M-CHECKED, so a parser failure cannot pass as a clean manifest.
AWK_PROG='
function attr(tag, key,    re) {
  re = " " key "=\"[^\"]*\""
  if (match(tag, re)) return substr(tag, RSTART + length(key) + 3, RLENGTH - length(key) - 4)
  return "(absent)"
}
function bad(msg) { print msg }
function open_tag(name, tag,    pn) {
  if (name == "manifest") {
    seen = 1
    pkg = attr(tag, "package")
  } else if (name == "uses-permission" || name == "uses-permission-sdk-23") {
    pn = attr(tag, "android:name")
    have[pn] = 1
    if (!(pn in allowedperm) && pn != pkg ".DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION") bad("uses-permission not allowlisted: " pn)
  } else if (name == "permission") {
    pn = attr(tag, "android:name")
    if (pn != pkg ".DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION") bad("declares a permission other than the app dynamic-receiver permission: " pn)
    else if (attr(tag, "android:protectionLevel") != "signature") bad(pn ": must have protectionLevel=\"signature\"")
  } else if (name == "application") {
    if (attr(tag, "android:allowBackup") != "false") bad("application must keep android:allowBackup=\"false\" (FR-7.9)")
    if (attr(tag, "android:usesCleartextTraffic") == "true") bad("application must not allow cleartext traffic (ADR-01)")
    if (attr(tag, "android:debuggable") == "true") bad("release application must not be debuggable")
  } else if (name == "activity" || name == "activity-alias" || name == "service" || name == "receiver" || name == "provider") {
    incomp = 1
    ctype = name
    cname = attr(tag, "android:name")
    cexported = attr(tag, "android:exported")
    cperm = attr(tag, "android:permission")
    cfilter = 0
    claunch = 0
  } else if (incomp && name == "intent-filter") {
    cfilter = 1
    fmain = 0
    flaunch = 0
  } else if (incomp && name == "action") {
    if (attr(tag, "android:name") == "android.intent.action.MAIN") fmain = 1
  } else if (incomp && name == "category") {
    if (attr(tag, "android:name") == "android.intent.category.LAUNCHER") flaunch = 1
  }
}
function close_tag(name) {
  if (incomp && name == "intent-filter") {
    if (fmain && flaunch) claunch = 1
  } else if (incomp && name == ctype) {
    end_component()
  }
}
function end_component() {
  incomp = 0
  if (cname == syncsvc) {
    foundsync = 1
    if (cexported != "false") bad(cname ": must declare android:exported=\"false\" (ADR-20)")
    if (cperm != "android.permission.BIND_JOB_SERVICE") bad(cname ": must be protected by android.permission.BIND_JOB_SERVICE (ADR-20)")
  }
  if (cexported == "(absent)" && cfilter) {
    bad(cname ": " ctype " with an intent filter must declare android:exported")
    return
  }
  if (cexported != "true") return
  if (ctype == "activity" && claunch) {
    launchers++
    return
  }
  if (cname in allowedexp) {
    if (cperm != allowedexp[cname]) bad(cname ": exported, must require " allowedexp[cname])
    return
  }
  bad(cname ": exported " ctype " is neither the LAUNCHER activity nor on the ADR-referenced list")
}
BEGIN {
  RS = "<"
  n = split(perms, parts, "|")
  for (i = 1; i <= n; i++) allowedperm[parts[i]] = 1
  n = split(exported, entries, ";")
  for (i = 1; i <= n; i++) if (entries[i] != "") { split(entries[i], f, "|"); allowedexp[f[1]] = f[2] }
}
{
  rec = $0
  gsub(/[\t\r\n]/, " ", rec)
  if (incomment) { if (index(rec, "-->")) incomment = 0; next }
  if (substr(rec, 1, 3) == "!--") { if (!index(substr(rec, 4), "-->")) incomment = 1; next }
  c = substr(rec, 1, 1)
  if (c == "?" || c == "!") next
  gt = index(rec, ">")
  if (gt == 0) next
  tag = substr(rec, 1, gt - 1)
  if (c == "/") {
    name = substr(tag, 2)
    sub(/[ ].*$/, "", name)
    close_tag(name)
    next
  }
  name = tag
  sub(/[ \/].*$/, "", name)
  open_tag(name, " " substr(tag, length(name) + 1))
  if (tag ~ /\/[ ]*$/) close_tag(name)
}
END {
  if (!seen) bad("not an Android manifest")
  if (!foundsync) bad(syncsvc ": missing (the background sync job, ADR-20)")
  n = split(required, req, "|")
  for (i = 1; i <= n; i++) if (!(req[i] in have)) bad("uses-permission missing: " req[i] " (the sync job needs it, ADR-20)")
  if (launchers != 1) bad("expected exactly one exported LAUNCHER activity, found " (launchers + 0))
  print "T15M-CHECKED"
}
'

exported_list=""
for entry in ${MERGED_EXPORTED[@]+"${MERGED_EXPORTED[@]}"}; do exported_list="$exported_list;$entry"; done

files=("$@")
if [ "${#files[@]}" -eq 0 ]; then
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    files+=("$f")
  done < <(find "$GHOST_ROOT/android/app/build/intermediates/merged_manifest/release" -type f -name AndroidManifest.xml 2>/dev/null || true)
fi
[ "${#files[@]}" -gt 0 ] || fail "no merged release manifest under $GHOST_ROOT/android/app/build (run :app:assembleRelease first)"
for m in ${files[@]+"${files[@]}"}; do
  if [ ! -f "$m" ]; then fail "$m: not found"; continue; fi
  parsed=0
  while IFS= read -r v; do
    if [ "$v" = "T15M-CHECKED" ]; then parsed=1; else fail "$m: $v"; fi
  done < <(awk -v perms="$T15_ALLOWED_PERMISSIONS" -v exported="$exported_list" -v syncsvc="$SYNC_JOB_SERVICE" -v required="$SYNC_JOB_PERMISSIONS" "$AWK_PROG" "$m" || true)
  [ "$parsed" = 1 ] || fail "$m: could not be parsed"
  echo "[merged-manifest-lint] checked $m"
done
finish merged-manifest-lint
