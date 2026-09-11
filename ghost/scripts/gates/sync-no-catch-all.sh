#!/usr/bin/env bash
# Gate (Phase 7 design §11.2 #11, crash fidelity): the sync engine never catches what it did not
# expect. In android/sync/src/main there is no catch of Throwable, Exception, RuntimeException or
# any *Error type (Kotlin and Java, fully qualified or not), no runCatching, and no handler that
# would swallow a JVM error. An injected process death (an Error) must reach the top level, where
# the exit-gate harness asserts it arrived; the engine catches only NetworkException and
# IllegalArgumentException around a port call (design §1.6).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
SYNC_MAIN="$GHOST_ROOT/android/sync/src/main"
# Kotlin: catch (e: Throwable) / catch (_: java.lang.Exception) / catch (e: kotlin.Error) / catch (e: AssertionError) ...
KT_CATCH='catch\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s*((kotlin|java\.lang)\.)?(Throwable|Exception|RuntimeException|[A-Za-z0-9_]*Error)\s*\)'
# Java: catch (Throwable t) / catch (final Exception e) / multi-catch naming one of them.
JAVA_CATCH='catch\s*\(\s*(final\s+)?([A-Za-z0-9_.]+\s*\|\s*)*((java\.lang)\.)?(Throwable|Exception|RuntimeException|[A-Za-z0-9_]*Error)(\s*\|\s*[A-Za-z0-9_.]+)*\s+[A-Za-z_][A-Za-z0-9_]*\s*\)'
# Kotlin Result helpers that catch every Throwable, and handlers that outlive an error.
OTHER='\brunCatching\b|\.getOrElse\s*\{|\.recoverCatching\b|setDefaultUncaughtExceptionHandler|setUncaughtExceptionHandler'
checked=0
if [ -d "$SYNC_MAIN" ]; then
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    checked=$((checked + 1))
    hits="$(grep -nP -- "$KT_CATCH|$JAVA_CATCH|$OTHER" "$f" || true)"
    [ -z "$hits" ] || while IFS= read -r line; do fail "$f:$line (catch-all in the sync engine)"; done <<< "$hits"
  done < <(find "$SYNC_MAIN" -type f \( -name '*.kt' -o -name '*.java' \) 2>/dev/null)
fi
[ "$checked" -gt 0 ] || fail "$SYNC_MAIN: no sources found (the gate would pass vacuously)"
finish sync-no-catch-all
