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
# Phase 11 (design faza11-media.md 13.1, 16.1 last row; slice S3): the same rule covers `android/media`
# (the media store and engine: its crash enumeration, SCN-MA ... SCN-MF, relies on an injected crash
# reaching the top level, and its file operations catch the one typed `IOException`, never a catch-all).
# Slice S5 (the sender pipeline) is the later slice that widens the allowlist's path check on purpose:
# the isolated decoding service (`MediaDecodeService`, §9.2) answers a decoder failure with a typed
# refusal, so a malicious file cannot wedge a request, while an Error (an OOM, a hard crash)
# propagates and kills the instance — its death by a delivered image is the design's outcome, seen
# by the main process as DeadObjectException, and the sandbox holds no GHOST state the crash
# enumeration must see. Its two deliberate `catch (e: RuntimeException)` arms are allowlisted below
# with that reason, like the DM modules' UnsatisfiedLinkError catches; every other catch in
# `:media` is typed (IOException, IllegalStateException, IllegalArgumentException, SecurityException,
# RemoteException, UnsupportedOperationException). Its `src/main` must exist and hold sources.
#
# **How the sources are read** (§22.33 item 16, the evasion review of this gate). Each file is one
# string (`source-text.pl`) with its comments and string contents blanked and Kotlin backtick quoting
# removed, and every pattern allows any whitespace, newlines included, between its tokens: a
# `catch (` whose parameter is on the next line, a comment inside the parentheses, an annotation on
# the parameter (`catch (@Suppress("…") e: Exception)`), a trailing comma, a quoted name, and a type
# qualified by any package or written across lines (`java` / `.lang.Throwable`) are all the clause
# they spell. A clause is reported at the line it starts on, as matched with its whitespace squashed
# (so the allowlist names it as one line). Every Android production source set is also read for a
# **type alias or an import alias** of a catch-all type (`typealias Oops = Throwable`, `import
# java.lang.Exception as Oops`): the catch that names the alias would otherwise pass unseen.
#
# What a text gate cannot see: a catch-all reached through a type the patterns do not name (a
# library's own `…Throwable` subclass hierarchy, a generic helper declared outside Android production
# code that catches for its caller), and a JVM error swallowed without a catch (a `finally` that
# returns, an executor that drops a task's exception). Those are the reviewer's and the crash
# harness's, which injects errors and asserts they arrive.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v perl >/dev/null || { echo "perl not found" >&2; exit 2; }
SYNC_MAIN="$GHOST_ROOT/android/sync/src/main"
ENTITLEMENT_MAIN="$GHOST_ROOT/android/entitlement/src/main"
ALLOW="$GHOST_ROOT/scripts/gates/sync-no-catch-all.allow"

# One line per file to read: `<area> <path>`. `sync` and `entitlement` take no exception, `dm` is
# read against the allowlist, `alias` (every other Android production source) only for aliases.
list_files() {
  local area dir set module
  for area in sync entitlement; do
    dir="$GHOST_ROOT/android/$area/src/main"
    [ -d "$dir" ] && find "$dir" -type f \( -name '*.kt' -o -name '*.java' \) 2>/dev/null | sort | sed "s|^|$area |"
  done
  for module in messaging crypto-bridge media; do
    for set in main gate debug release; do
      dir="$GHOST_ROOT/android/$module/src/$set"
      [ -d "$dir" ] && find "$dir" -type f \( -name '*.kt' -o -name '*.java' \) 2>/dev/null | sort | sed "s|^|dm |"
    done
  done
  if [ -d "$GHOST_ROOT/android" ]; then
    find "$GHOST_ROOT/android" -path '*/build' -prune -o -type f \( -name '*.kt' -o -name '*.java' \) \
      \( -path '*/src/main/*' -o -path '*/src/release/*' -o -path '*/src/gate/*' -o -path '*/src/debug/*' \) -print 2>/dev/null \
      | grep -vE '/android/(sync|entitlement|messaging|crypto-bridge|media)/src/' | sort | sed 's|^|alias |' || true
  fi
  return 0
}

out="$(list_files | GHOST_ROOT="$GHOST_ROOT" GATES_DIR="$GATES_DIR" perl -e '
use strict; use warnings;
require "$ENV{GATES_DIR}/source-text.pl";
my $root = $ENV{GHOST_ROOT};
my $dot = qr/\s*\.\s*/;
# A catch-all type: Throwable, Exception, RuntimeException or any *Error, unqualified or qualified by
# any package (kotlin.Error, java.lang.Exception, java.io.IOError), a qualifier written across lines too.
my $type = qr/(?:[A-Za-z_]\w*$dot)*(?:Throwable|Exception|RuntimeException|\w*Error)\b(?!$dot\w)/;
my $annotation = qr/@[A-Za-z_][\w.]*(?:\s*\([^()]*\))?\s*/;
# Kotlin: catch (e: Throwable), with annotations, a trailing comma, newlines anywhere.
my $kt = qr/\bcatch\s*\(\s*(?:$annotation)*[A-Za-z_]\w*\s*:\s*$type\s*(?:,\s*)?\)/;
# Java: catch (Throwable t) / catch (final Exception e) / a multi-catch naming one of them.
my $java = qr/\bcatch\s*\(\s*(?:final\s+)?(?:$annotation)*(?:[\w.]+\s*\|\s*)*$type(?:\s*\|\s*[\w.]+)*\s+[A-Za-z_]\w*\s*\)/;
# Kotlin Result helpers that catch every Throwable, and handlers that outlive an error.
my $other = qr/\brunCatching\b|\.\s*getOrElse\s*\{|\.\s*recoverCatching\b|\bsetDefaultUncaughtExceptionHandler\b|\bsetUncaughtExceptionHandler\b/;
my $alias = qr/\btypealias\s+[A-Za-z_]\w*(?:\s*<[^<>=]*>)?\s*=\s*$type|\bimport\s+$type\s+as\s+[A-Za-z_]\w*/;
my %scanned;
while (my $entry = <STDIN>) {
  chomp $entry;
  my ($area, $file) = split / /, $entry, 2;
  next unless defined $file && length $file;
  (my $rel = $file) =~ s{^\Q$root\E/}{};
  $scanned{$area}++ if $area ne "dm" || $rel =~ m{/src/main/};
  my $text = read_text($file);
  my @lines = split /\n/, $text, -1;
  my (undef, $code) = views($text, $file =~ /\.java$/ ? "java" : "kotlin");
  while ($code =~ /$alias/g) {
    my $n = line_of(\$code, $-[0]);
    print "ALIAS\t$rel:$n: " . squash($&) . "\n";
  }
  next if $area eq "alias";
  my %line_seen;
  while ($code =~ /$kt|$java|$other/g) {
    my ($from, $clause) = ($-[0], squash($&));
    my $n = line_of(\$code, $from);
    if ($area eq "dm") { print "DM\t$rel\t$n\t$clause\n"; next; }
    next if $line_seen{$n}++;
    my $shown = $clause =~ /\n/ || $lines[$n - 1] !~ /\Q$clause\E/ ? $clause : $lines[$n - 1];
    print "STRICT\t$rel:$n:$shown\n";
  }
}
print "SCANNED\t$_ $scanned{$_}\n" for sort keys %scanned;
')" || { echo "sync-no-catch-all: the scanner stopped" >&2; exit 2; }

declare -A allowed=() found=() where=() scanned=()
while IFS= read -r line; do
  kind="${line%%$'\t'*}"
  rest="${line#*$'\t'}"
  case "$kind" in
    STRICT) fail "$GHOST_ROOT/$rest (catch-all in the sync engine or its participant)" ;;
    ALIAS) fail "$GHOST_ROOT/$rest (an alias of a catch-all type: a catch that names it would pass this gate unseen)" ;;
    DM)
      IFS=$'\t' read -r rel at clause <<< "$rest"
      key="$rel|$clause"
      found["$key"]=$(( ${found["$key"]:-0} + 1 ))
      where["$key"]="${where["$key"]:-}$rel:$at "
      ;;
    SCANNED) scanned["${rest% *}"]="${rest##* }" ;;
  esac
done <<< "$out"

[ "${scanned[sync]:-0}" -gt 0 ] || fail "$SYNC_MAIN: no sources found (the gate would pass vacuously)"
[ -d "$ENTITLEMENT_MAIN" ] || fail "$ENTITLEMENT_MAIN: missing (the gate would pass vacuously)"

# The DM modules, against the allowlist. Every hit is keyed by (path relative to GHOST_ROOT, the
# clause as matched with its whitespace squashed); the allowlist gives each key its exact count.
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
      android/messaging/src/*|android/crypto-bridge/src/*|android/media/src/*) ;;
      *) fail "scripts/gates/sync-no-catch-all.allow:$n: $path is outside the DM modules (the sync engine and its participant take no exception)"; continue ;;
    esac
    allowed["$path|$clause"]="$count"
  done < "$ALLOW"
fi
for module in messaging crypto-bridge media; do
  [ -d "$GHOST_ROOT/android/$module/src/main" ] || fail "$GHOST_ROOT/android/$module/src/main: missing (the gate would pass vacuously)"
done
for module in messaging media; do
  [ ! -d "$GHOST_ROOT/android/$module/src/main" ] \
    || [ -n "$(find "$GHOST_ROOT/android/$module/src/main" -type f \( -name '*.kt' -o -name '*.java' \) 2>/dev/null | head -n 1)" ] \
    || fail "$GHOST_ROOT/android/$module/src/main: no sources found (the gate would pass vacuously)"
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
