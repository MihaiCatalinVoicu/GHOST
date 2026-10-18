#!/usr/bin/env bash
# Gate G-U5 (Phase 13 design faza13-ux.md §13.1, §3.1; invariant T53): the :ui module is
# isolated — no project() dependency, no engine package, no network/storage/file API — and the
# traffic-causing facade methods of :app are called only from the allowlisted adapter files.
#
# The :ui half:
#   ui/build.gradle.kts declares no project( dependency
#   android/ui names no org.ghost. package outside org.ghost.ui
#   no network, SQLite or file-writing API (the lists of kotlin-clearnet.sh and G-DM1, plus
#   SQLite, File writes, openFileOutput); android.net. only as android.net.Uri in SystemIntents.kt
# The :app half (the traffic list of §2.4/§13.1):
#   every call of a listed method only from the files of ui-traffic-callers.allow, each with a
#   reason (G-DM2's pattern)
# The gateway half (PV-14):
#   in :ui, a call of a gateway method annotated @UserAction only from on… intent handlers of
#   *Model.kt files

set -euo pipefail
GATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="${GHOST_ROOT:-$(cd "$GATES_DIR/../.." && pwd)}"
FAILURES=0
fail() { echo "GATE-FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }

# --- :ui half ---
UI_BUILD="$GHOST_ROOT/android/ui/build.gradle.kts"
if [ -f "$UI_BUILD" ]; then
  # Comment lines are not declarations; only a non-comment line may declare the dependency.
  if grep -vE '^\s*(//|\*)' "$UI_BUILD" | grep -q 'project('; then
    fail "ui/build.gradle.kts declares a project() dependency"
  fi
else
  fail "ui/build.gradle.kts missing"
fi

NET_RE='\b(java\.net|javax\.net|android\.net(?!\.Uri)|okhttp3|io\.ktor|retrofit2|com\.android\.volley|org\.apache\.http)\b|\b(Socket|ServerSocket|DatagramSocket|HttpURLConnection|WebView)\b'
STORE_RE='\b(android\.database|androidx\.sqlite|net\.sqlcipher|java\.sql|SQLiteDatabase)\b|\b(openFileOutput|FileOutputStream|java\.io\.File)\b'
while IFS= read -r f; do
  rel="${f#"$GHOST_ROOT"/}"
  hits=$(perl -e '
    require "'"$GATES_DIR"'/source-text.pl";
    my $t = read_text($ARGV[0]);
    my ($w, $c) = views($t, "kotlin");
    my @bad;
    while ($c =~ /'"\bjava\.net\b|\bjavax\.net\b|\bokhttp3\b|\bio\.ktor\b|\bretrofit2\b|\bcom\.android\.volley\b|\borg\.apache\.http\b|\bSocket\b|\bServerSocket\b|\bDatagramSocket\b|\bHttpURLConnection\b|\bWebView\b"'/g) { push @bad, "network API at line " . line_of(\$c, $-[0]); }
    while ($c =~ /'"\bandroid\.database\b|\bandroidx\.sqlite\b|\bnet\.sqlcipher\b|\bjava\.sql\b|\bSQLiteDatabase\b|\bopenFileOutput\b|\bFileOutputStream\b|\bjava\.io\.File\b"'/g) { push @bad, "storage/file API at line " . line_of(\$c, $-[0]); }
    # android.net: only the bare type Uri, and only in SystemIntents.kt
    while ($c =~ /\bandroid\.net\.([A-Za-z0-9_]+)/g) {
      my $what = $1;
      push @bad, "android.net.$what at line " . line_of(\$c, $-[0]) unless $what eq "Uri" && $ARGV[1] eq "ok";
    }
    print join("\n", @bad);
  ' "$f" "$([ "$rel" = "android/ui/src/main/kotlin/org/ghost/ui/platform/SystemIntents.kt" ] && echo ok || echo no)")
  if [ -n "$hits" ]; then
    while IFS= read -r h; do fail "$rel: $h"; done <<< "$hits"
  fi
done < <(find "$GHOST_ROOT/android/ui/src/main" -type f -name '*.kt' 2>/dev/null || true)

# :ui names no org.ghost. package outside org.ghost.ui (imports).
while IFS= read -r f; do
  rel="${f#"$GHOST_ROOT"/}"
  hits=$(grep -nE 'import +org\.ghost\.[a-z]' "$f" | grep -v 'import org\.ghost\.ui\.' || true)
  [ -z "$hits" ] || while IFS= read -r h; do fail "$rel: engine package reference: $h"; done <<< "$hits"
done < <(find "$GHOST_ROOT/android/ui/src/main" -type f -name '*.kt' 2>/dev/null || true)

# --- :app traffic half ---
ALLOW="$GATES_DIR/ui-traffic-callers.allow"
[ -f "$ALLOW" ] || { fail "ui-traffic-callers.allow missing"; }
if [ -f "$ALLOW" ]; then
  TRAFFIC='\.(send|react|setTimer|retry|resetSession|reconnect|issueRevocation|notifyContactsOfRevocation)\s*\(|\.(create|createInvite|acceptInvite|post|remove|leave|setPolicy|reveal|resync)\s*\(|\.(sendMedia|retryMedia|setDownloadsPaused)\s*\(|\.(activate|activateGenesis|startPurchase|requestInvoiceNow|checkNow|claimPayout|revokeInvite|setAutoRenewWithCredits|paymentInstructions|paymentScreenShown|paymentScreenHidden)\s*\(|\.(requestExpedite|onAppForeground|onAppBackground|setPrivacyMode|runUserIssuerCall)\s*\(|\.(requestCheck|requestDownload|install)\s*\('
  while IFS= read -r f; do
    rel="${f#"$GHOST_ROOT"/}"
    case "$rel" in android/app/src/*/kotlin/org/ghost/app/ui/*) continue ;; esac
    # The gate build type's instrumentation drives the engines on purpose (§12.3); it is not
    # production UI and the allowlist does not cover it.
    case "$rel" in */src/gate/*) continue ;; esac
    case "$rel" in android/app/src/*) ;;
      *) continue ;;
    esac
    hits=$(grep -nE "$TRAFFIC" "$f" || true)
    if [ -n "$hits" ]; then
      # Allowed if this file is on the allowlist (a line 'path<TAB>reason').
      while IFS= read -r h; do
        hline=$(printf '%s' "$h" | cut -d: -f1)
        fname=$(printf '%s' "$h" | cut -d: -f2-)
        reason=$(awk -v p="$rel" '$1 == p {print $2; exit}' FS='\t' "$ALLOW")
        [ -n "$reason" ] || fail "$rel:$hline: traffic-causing call outside the adapter allowlist: $fname"
      done <<< "$hits"
    fi
  done < <(find "$GHOST_ROOT/android/app/src" -path '*/build' -prune -o -type f -name '*.kt' -print 2>/dev/null | grep -v '/src/test/\|/src/androidTest/' || true)
fi

# --- gateway half: @UserAction calls only from on… handlers in *Model.kt of :ui ---
while IFS= read -r f; do
  rel="${f#"$GHOST_ROOT"/}"
  case "$rel" in
    *Model.kt) ;;
    *)
      if grep -q '@UserAction\|\.userAction' "$f"; then
        fail "$rel: names a @UserAction gateway call outside a *Model.kt intent handler"
      fi
      ;;
  esac
done < <(find "$GHOST_ROOT/android/ui/src/main" -type f -name '*.kt' 2>/dev/null || true)

if [ "$FAILURES" -gt 0 ]; then echo "[ui-isolation] FAILED with $FAILURES violation(s)" >&2; exit 1; fi
echo "[ui-isolation] OK"
