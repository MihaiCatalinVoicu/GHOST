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
    grep -q 'android:allowBackup="false"' "$m" || fail "$m: application must declare android:allowBackup=\"false\" (FR-7.9)"
    grep -q 'android:dataExtractionRules=' "$m" || fail "$m: application must declare android:dataExtractionRules (FR-7.9)"
    grep -q 'android:fullBackupContent=' "$m" || fail "$m: application must declare android:fullBackupContent (FR-7.9)"
    grep -q 'android:networkSecurityConfig=' "$m" || fail "$m: application must declare android:networkSecurityConfig (ADR-01)"
    exported="$(grep -c 'android:exported="true"' "$m" || true)"
    if [ "${exported:-0}" -gt 1 ]; then fail "$m: more than one exported component ($exported); each needs an ADR"; fi
    if [ "${exported:-0}" -eq 1 ] && ! grep -q 'android.intent.category.LAUNCHER' "$m"; then
      fail "$m: exported component without LAUNCHER intent filter"
    fi
  fi
  grep -qiE 'firebase|gms|com\.google\.android\.gms|analytics|crashlytics' "$m" && fail "$m: Google services / analytics reference (ADR-06)"
done < <(manifest_files)
finish manifest-lint
