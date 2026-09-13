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
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
SYNC_MAIN="$GHOST_ROOT/android/sync/src/main"
ENTITLEMENT_MAIN="$GHOST_ROOT/android/entitlement/src/main"
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
finish sync-no-catch-all
