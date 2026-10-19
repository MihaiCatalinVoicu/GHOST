#!/usr/bin/env bash
# Gate T15 (FR-7.9, ADR-06, ADR-08): every Android manifest on the production path is hardened.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
# The allowlist is T15_ALLOWED_PERMISSIONS in common.sh (ADR references there); the merged release
# manifest is checked by merged-manifest-lint.sh (T15m) after the build.
ALLOWED_PERMISSIONS="$T15_ALLOWED_PERMISSIONS"
while IFS= read -r m; do
  [ -n "$m" ] || continue
  # Permissions: only the allowlisted set (each addition needs an ADR reference).
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    echo "$p" | grep -qE "^($ALLOWED_PERMISSIONS)$" || fail "$m: permission not allowlisted: $p"
  done < <(grep -oP 'uses-permission[^>]*android:name="\K[^"]+' "$m" || true)
  grep -q 'usesCleartextTraffic="true"' "$m" && fail "$m: usesCleartextTraffic=true is forbidden (ADR-01)"
  if grep -q '<application' "$m"; then
    case "$m" in
      # T4's control application (design faza13-ux.md Appendix B.2): its entire purpose is the
      # relaxed backup posture that proves the pipeline carried data - the hardening attributes
      # below would defeat it. The other rules of this gate still apply to it.
      *backupctl*) ;;
      *)
    grep -q 'android:allowBackup="false"' "$m" || fail "$m: application must declare android:allowBackup=\"false\" (FR-7.9)"
    grep -q 'android:dataExtractionRules=' "$m" || fail "$m: application must declare android:dataExtractionRules (FR-7.9)"
    grep -q 'android:fullBackupContent=' "$m" || fail "$m: application must declare android:fullBackupContent (FR-7.9)"
    grep -q 'android:networkSecurityConfig=' "$m" || fail "$m: application must declare android:networkSecurityConfig (ADR-01)"
        ;;
    esac
    exported="$(grep -c 'android:exported="true"' "$m" || true)"
    if [ "${exported:-0}" -gt 1 ]; then fail "$m: more than one exported component ($exported); each needs an ADR"; fi
    if [ "${exported:-0}" -eq 1 ] && ! grep -q 'android.intent.category.LAUNCHER' "$m"; then
      fail "$m: exported component without LAUNCHER intent filter"
    fi
  fi
  grep -qiE 'firebase|gms|com\.google\.android\.gms|analytics|crashlytics' "$m" && fail "$m: Google services / analytics reference (ADR-06)"
  # G-M4 (Phase 11 design faza11-media.md §16.1 G-M4; slice S7): the isolated decoding service
  # is declared exactly as §9.2 names it, and the merged manifest keeps no FileProvider or the
  # GMS picker backport's module-dependencies marker.
  grep -q 'FileProvider' "$m" && fail "$m: FileProvider is forbidden (G-M4, §10.3)"
  grep -q 'com.google.android.gms.metadata.ModuleDependencies' "$m" && fail "$m: the GMS picker backport marker is forbidden (ADR-06, G-M4)"
  if grep -q 'org.ghost.media.sandbox.MediaDecodeService' "$m"; then
    awk_prog='
      function attr(tag, key,    re) {
        re = " " key "=\"[^\"]*\""
        if (match(tag, re)) return substr(tag, RSTART + length(key) + 3, RLENGTH - length(key) - 4)
        return "(absent)"
      }
      function open_tag(name, tag) {
        if (name == "service") {
          inservice = 1
          sexp = attr(tag, "android:exported")
          sisol = attr(tag, "android:isolatedProcess")
          sproc = attr(tag, "android:process")
          sname = attr(tag, "android:name")
          sfilter = 0
          if (tag ~ /\/[ ]*$/) end_service()
        } else if (inservice && name == "intent-filter") {
          sfilter = 1
        } else if (name == "provider") {
          providers++
        }
      }
      function close_tag(name) {
        if (name == "service") end_service()
      }
      function end_service() {
        if (!inservice) return
        inservice = 0
        if (sname != svc) return
        found++
        if (sexp != "false") bad(svc ": must declare android:exported=\"false\" (G-M4)")
        if (sisol != "true") bad(svc ": must declare android:isolatedProcess=\"true\" (G-M4)")
        if (sproc != ":mdec") bad(svc ": must run in the :mdec process (G-M4)")
        if (sfilter) bad(svc ": must have no intent filter (G-M4)")
      }
      function bad(msg) { print msg }
      BEGIN { RS = "<"; svc = "org.ghost.media.sandbox.MediaDecodeService" }
      {
        rec = $0
        gsub(/[\t\r\n]/, " ", rec)
        c = substr(rec, 1, 1)
        if (c == "?" || c == "!") next
        gt = index(rec, ">")
        if (gt == 0) next
        tag = substr(rec, 1, gt - 1)
        if (c == "/") { close_tag(substr(tag, 2)); next }
        name = tag
        sub(/[ \/].*$/, "", name)
        open_tag(name, " " substr(tag, length(name) + 1))
      }
      END {
        if (found != 1) bad("expected exactly one " svc " service, found " found + 0)
      }
    '
    while IFS= read -r v; do
      fail "$m: $v"
    done < <(awk "$awk_prog" "$m" || true)
  fi
done < <(manifest_files)

# G-M4's source half (Phase 11 design faza11-media.md §16.1 G-M4; slice S7): the isolated
# service is bound only through bindIsolatedService, only from org.ghost.media.sandbox, and
# never with BIND_SHARED_ISOLATED_PROCESS (a shared isolated process would let two requests
# meet in one instance, PM-M21's shape).
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in
    */org/ghost/media/sandbox/*) : ;;
    *)
      while IFS= read -r hit; do
        [ -n "$hit" ] || continue
        fail "${f#"$GHOST_ROOT"/}: $hit (G-M4: only org.ghost.media.sandbox binds the isolated service)"
      done < <(grep -n 'bindIsolatedService' "$f" 2>/dev/null || true)
      ;;
  esac
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    fail "${f#"$GHOST_ROOT"/}: $hit (G-M4: BIND_SHARED_ISOLATED_PROCESS is forbidden)"
  done < <(grep -n 'BIND_SHARED_ISOLATED_PROCESS' "$f" 2>/dev/null || true)
done < <({ android_main_files; android_gate_files; } | sort -u)
finish manifest-lint
