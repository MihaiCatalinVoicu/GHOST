#!/usr/bin/env bash
# Gate (Phase 7 design §11.2 #11, crash fidelity): the sync engine never catches what it did not
# expect. In android/sync/src/main there is no catch of Throwable, Exception, RuntimeException or
# any *Error type (Kotlin and Java, fully qualified or not), no runCatching, and no handler that
# would swallow a JVM error. An injected process death (an Error) must reach the top level, where
# the exit-gate harness asserts it arrived; the engine catches only NetworkException and
# IllegalArgumentException around a port call (design §1.6).
# Phase 8 (design §11.1, RC G17): the same rule covers android/entitlement/src/main, the session
# participant of the sync runtime, whose crash enumeration relies on it too. The entitlement
# module's main source directory must exist (a moved module would otherwise pass vacuously); it
# may hold no Kotlin yet, the sync engine must.
# Phase 9 (design §16.1 last rows, §22.11 item 9(c); S0′ gate slice, §22.33): the same rule covers the
# DM modules, android/messaging and android/crypto-bridge — their production source sets `src/main`,
# and `src/gate`, `src/debug`, `src/release` where they exist — whose crash enumeration (SCN-A …
# SCN-L) relies on an injected crash reaching the top level exactly as the sync engine's does. Their
# typed catches (StorageFullException, InsufficientReplicasException, the executor's and the JCA's
# checked exceptions) are not catch-alls and pass. What the DM modules deliberately catch is listed,
# with its reason and its exact count per file, in `scripts/gates/sync-no-catch-all.allow` (read under
# GHOST_ROOT, so each fixture carries its own): a clause found more often than its entry allows fails
# every occurrence, an entry whose clause is found fewer times than it says is stale and fails, and
# the allowlist can name nothing outside the two DM modules. Both DM modules' `src/main` must exist
# and `android/messaging/src/main` must hold sources.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
SYNC_MAIN="$GHOST_ROOT/android/sync/src/main"
ENTITLEMENT_MAIN="$GHOST_ROOT/android/entitlement/src/main"
ALLOW="$GHOST_ROOT/scripts/gates/sync-no-catch-all.allow"
# Kotlin: catch (e: Throwable) / catch (_: java.lang.Exception) / catch (e: kotlin.Error) / catch (e: AssertionError) ...
KT_CATCH='catch\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s*((kotlin|java\.lang)\.)?(Throwable|Exception|RuntimeException|[A-Za-z0-9_]*Error)\s*\)'
# Java: catch (Throwable t) / catch (final Exception e) / multi-catch naming one of them.
JAVA_CATCH='catch\s*\(\s*(final\s+)?([A-Za-z0-9_.]+\s*\|\s*)*((java\.lang)\.)?(Throwable|Exception|RuntimeException|[A-Za-z0-9_]*Error)(\s*\|\s*[A-Za-z0-9_.]+)*\s+[A-Za-z_][A-Za-z0-9_]*\s*\)'
# Kotlin Result helpers that catch every Throwable, and handlers that outlive an error.
OTHER='\brunCatching\b|\.getOrElse\s*\{|\.recoverCatching\b|setDefaultUncaughtExceptionHandler|setUncaughtExceptionHandler'
# Scans every Kotlin and Java source under $1; prints the number of files scanned.
scan() {
  local root="$1" n=0 f hits line
  if [ -d "$root" ]; then
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      n=$((n + 1))
      hits="$(grep -nP -- "$KT_CATCH|$JAVA_CATCH|$OTHER" "$f" || true)"
      [ -z "$hits" ] || while IFS= read -r line; do fail "$f:$line (catch-all in the sync engine or its participant)"; done <<< "$hits"
    done < <(find "$root" -type f \( -name '*.kt' -o -name '*.java' \) 2>/dev/null)
  fi
  SCANNED=$n
}
SCANNED=0
scan "$SYNC_MAIN"
[ "$SCANNED" -gt 0 ] || fail "$SYNC_MAIN: no sources found (the gate would pass vacuously)"
[ -d "$ENTITLEMENT_MAIN" ] || fail "$ENTITLEMENT_MAIN: missing (the gate would pass vacuously)"
scan "$ENTITLEMENT_MAIN"

# The DM modules, against the allowlist. Every hit is keyed by (path relative to GHOST_ROOT, the
# clause as matched with its whitespace squashed); the allowlist gives each key its exact count.
declare -A allowed=() found=() where=()
if [ -f "$ALLOW" ]; then
  n=0
  while IFS= read -r entry; do
    n=$((n + 1))
    case "$entry" in ''|'#'*) continue ;; esac
    IFS='|' read -r path clause count reason <<< "$entry"
    if [ -z "$path" ] || [ -z "$clause" ] || ! [[ "$count" =~ ^[1-9][0-9]*$ ]] || [ -z "$reason" ]; then
      fail "scripts/gates/sync-no-catch-all.allow:$n: malformed entry (path|clause|count|reason, every field set)"; continue
    fi
    case "$path" in
      android/messaging/src/*|android/crypto-bridge/src/*) ;;
      *) fail "scripts/gates/sync-no-catch-all.allow:$n: $path is outside the DM modules (the sync engine and its participant take no exception)"; continue ;;
    esac
    allowed["$path|$clause"]="$count"
  done < "$ALLOW"
fi
for module in messaging crypto-bridge; do
  [ -d "$GHOST_ROOT/android/$module/src/main" ] || fail "$GHOST_ROOT/android/$module/src/main: missing (the gate would pass vacuously)"
  SCANNED=0
  for set in main gate debug release; do
    dir="$GHOST_ROOT/android/$module/src/$set"
    [ -d "$dir" ] || continue
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      [ "$set" = main ] && SCANNED=$((SCANNED + 1))
      rel="${f#"$GHOST_ROOT"/}"
      hits="$(grep -noP -- "$KT_CATCH|$JAVA_CATCH|$OTHER" "$f" || true)"
      [ -n "$hits" ] || continue
      while IFS= read -r hit; do
        clause="$(sed -E 's/[[:space:]]+/ /g' <<< "${hit#*:}")"
        key="$rel|$clause"
        found["$key"]=$(( ${found["$key"]:-0} + 1 ))
        where["$key"]="${where["$key"]:-}$rel:${hit%%:*} "
      done <<< "$hits"
    done < <(find "$dir" -type f \( -name '*.kt' -o -name '*.java' \) 2>/dev/null | sort)
  done
  [ "$module" != messaging ] || [ "$SCANNED" -gt 0 ] || fail "$GHOST_ROOT/android/messaging/src/main: no sources found (the gate would pass vacuously)"
done
for key in "${!found[@]}"; do
  want="${allowed["$key"]:-0}"
  if [ "${found["$key"]}" -gt "$want" ]; then
    for at in ${where["$key"]}; do
      fail "$GHOST_ROOT/$at: ${key#*|} (catch-all in a DM module: ${found["$key"]} found, the allowlist permits $want in this file)"
    done
  fi
done
for key in "${!allowed[@]}"; do
  have="${found["$key"]:-0}"
  if [ "$have" -lt "${allowed["$key"]}" ]; then
    fail "scripts/gates/sync-no-catch-all.allow: stale entry ${key%%|*} '${key#*|}' (${allowed["$key"]} allowed, $have found): remove or correct it"
  fi
done
finish sync-no-catch-all
