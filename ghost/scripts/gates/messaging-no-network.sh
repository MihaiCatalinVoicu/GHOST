#!/usr/bin/env bash
# Gate G-DM1 (Phase 9 design §16.1; invariant T28, ADR-20; S0′ gate slice, §22.33): **the DM modules
# never touch the network themselves.** `android/messaging` and `android/crypto-bridge` reach a relay
# only through the `:sync` API (the outbox, the inbox, the registration lane), so every relay-visible
# action is one the sync engine schedules, pads and paces (T28: nothing a DM step does is a network
# reflex; ADR-20: the only network work is the sync job and its foreground session). Their production
# sources may therefore name none of:
#   - `org.ghost.network` (the transport module; `:messaging` sees it through `:sync`'s `api`
#     dependency, which is exactly why a text gate is needed: the compiler would accept the import);
#   - `java.net`, `javax.net` (sockets, URLs, name resolution, socket factories, TLS);
#   - `android.net` and `android.webkit` (connectivity, local sockets, HTTP helpers, web views);
#   - a socket, channel, address or HTTP client class by its bare name, as a whole word (after a
#     wildcard import the name is all that is left on the line that uses it): `Socket`,
#     `ServerSocket`, `DatagramSocket`, `MulticastSocket`, `SocketChannel`, `ServerSocketChannel`,
#     `DatagramChannel`, `AsynchronousSocketChannel`, `AsynchronousServerSocketChannel`,
#     `LocalSocket`, `LocalServerSocket`, `SSLSocket`, `SSLSocketFactory`, `SocketFactory`, `URL`,
#     `URLConnection`, `HttpURLConnection`, `HttpsURLConnection`, `HttpClient`, `OkHttpClient`,
#     `InetAddress`, `Inet4Address`, `Inet6Address`, `InetSocketAddress`, `WebView`;
#   - an HTTP library package: `okhttp3`, `io.ktor`, `retrofit2`, `com.android.volley`,
#     `org.apache.http`;
#   - `kotlinx.coroutines`, and the standard library's own `kotlin.coroutines` (ADR-20: no coroutines
#     in GHOST code; the DM actor is one thread, §13.7);
#   - the `suspend` modifier, in code: a suspending function, function type or lambda is a coroutine
#     whatever it imports (`suspend fun`, `suspend () -> Unit`, `suspend Step.() -> Unit`).
#
# Production sources are every Kotlin and Java file of the two modules' non-test source sets:
# `src/main`, and `src/gate`, `src/debug`, `src/release` where they exist (the `gate` build type is
# installed on the gate devices, §21.13 point 7). `src/test`, `src/androidTest`, `src/deviceRunner`
# and `src/equivalence` are test code and are not read.
#
# Two readings (§22.33 item 16, the evasion review of this gate). **As written, one line at a time**,
# like `dm-no-fts.sh` and `kotlin-clearnet.sh`: a **comment** that names a banned package or class
# fails too, on purpose — a gate that had to tell prose from code would be a Kotlin parser with a
# parser's blind spots; say it in the design document or in a test instead. **Then the whole file as
# one string** (`source-text.pl`), comments and Kotlin backtick quoting removed, with any whitespace,
# newlines included, allowed around each dot: a qualified name written across lines (`java` / `.net`
# / `.ProxySelector`, legal Kotlin in code and in an import), split by a comment (`java/**/.net`) or
# quoted (`` `java`.`net` ``) is the package it names; and `suspend` is read in code only (comments
# and strings blanked), where no line break or comment can hide it.
#
# What a text gate cannot see: a name built at run time (`Class.forName("java." + "net.Socket")`,
# reflection over a string it did not write whole), a type alias or an import alias declared in
# another module (the reason `:messaging` has no dependency on `:network` of its own, §13.1), and a
# network class of a library this list does not name. Those are the reviewer's.
#
# Vacuity: both modules' `src/main` must exist and hold at least one source, or the gate fails
# rather than pass over a moved module.
#
# Usage: messaging-no-network.sh        (scans GHOST_ROOT, default: the ghost/ monorepo)
# Self-test: scripts/gates/self-test.sh points GHOST_ROOT at test-harness/gates/negative-dm-network-*.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v perl >/dev/null || { echo "perl not found" >&2; exit 2; }

files=()
for module in messaging crypto-bridge; do
  for set in main gate debug release; do
    dir="$GHOST_ROOT/android/$module/src/$set"
    [ -d "$dir" ] || continue
    while IFS= read -r f; do
      [ -n "$f" ] && files+=("$f")
    done < <(find "$dir" -type f \( -name '*.kt' -o -name '*.java' \) 2>/dev/null | sort)
  done
done

out="$(printf '%s\n' "${files[@]+"${files[@]}"}" | GHOST_ROOT="$GHOST_ROOT" GATES_DIR="$GATES_DIR" perl -e '
use strict; use warnings;
require "$ENV{GATES_DIR}/source-text.pl";
my $root = $ENV{GHOST_ROOT};
my @packages = qw(org.ghost.network java.net javax.net android.net android.webkit kotlinx.coroutines
  kotlin.coroutines okhttp3 io.ktor retrofit2 com.android.volley org.apache.http);
my $on_a_line = join "|", map { "\\b" . quotemeta($_) . "\\b" } @packages;
# The same names with any whitespace, newlines included, around each dot, over a view without
# comments and backtick quoting: `java` / `.net`, `java/**/.net` and `java` in backticks all read java.net.
my $spread = join "|", map { "\\b" . join("\\s*\\.\\s*", map { quotemeta } split /\./) . "\\b" } @packages;
my $classes = qr/\b(?:Socket|ServerSocket|DatagramSocket|MulticastSocket|SocketChannel|ServerSocketChannel|DatagramChannel|AsynchronousSocketChannel|AsynchronousServerSocketChannel|LocalSocket|LocalServerSocket|SSLSocket|SSLSocketFactory|SocketFactory|URL|URLConnection|HttpURLConnection|HttpsURLConnection|HttpClient|OkHttpClient|InetAddress|Inet4Address|Inet6Address|InetSocketAddress|WebView)\b/;
my %scanned;
while (my $file = <STDIN>) {
  chomp $file;
  next unless length $file;
  (my $rel = $file) =~ s{^\Q$root\E/}{};
  my ($module, $set) = $rel =~ m{^android/([^/]+)/src/([^/]+)/};
  $scanned{$module}++ if $set eq "main";
  my $text = read_text($file);
  my @lines = split /\n/, $text, -1;
  my (%pkg, %cls, %sus);
  # As written, one line at a time: a comment that names a banned package or class fails too.
  for my $i (0 .. $#lines) {
    my $n = $i + 1;
    if ($lines[$i] =~ /$on_a_line/) { $pkg{$n} = 1; print "PKG\t$rel:$n:$lines[$i]\n"; }
    if ($lines[$i] =~ $classes) { $cls{$n} = 1; print "CLS\t$rel:$n:$lines[$i]\n"; }
  }
  my ($with, $code) = views($text, $rel =~ /\.java$/ ? "java" : "kotlin");
  # The whole file: what the line reading cannot see, each finding once per line.
  while ($with =~ /$spread/g) {
    my $n = line_of(\$with, $-[0]);
    next if $pkg{$n}++;
    print "PKG\t$rel:$n:" . squash($&) . " (written across lines, split by a comment or quoted)\n";
  }
  while ($with =~ /$classes/g) {
    my $n = line_of(\$with, $-[0]);
    next if $cls{$n}++;
    print "CLS\t$rel:$n:" . squash($&) . "\n";
  }
  while ($code =~ /\bsuspend\b/g) {
    my $n = line_of(\$code, $-[0]);
    next if $sus{$n}++;
    print "SUS\t$rel:$n:$lines[$n - 1]\n";
  }
}
print "SCANNED\t$_ $scanned{$_}\n" for sort keys %scanned;
')" || { echo "messaging-no-network: the scanner stopped" >&2; exit 2; }

declare -A scanned=()
while IFS= read -r line; do
  kind="${line%%$'\t'*}"
  rest="${line#*$'\t'}"
  case "$kind" in
    PKG) fail "$rest (G-DM1: a DM module names a network package; the only way to a relay is the :sync API)" ;;
    CLS) fail "$rest (G-DM1: a DM module names a socket, address or HTTP class)" ;;
    SUS) fail "$rest (G-DM1: a suspend modifier is a coroutine; ADR-20, the DM actor is one thread, §13.7)" ;;
    SCANNED) scanned["${rest% *}"]="${rest##* }" ;;
  esac
done <<< "$out"
for module in messaging crypto-bridge; do
  main="$GHOST_ROOT/android/$module/src/main"
  [ -d "$main" ] || fail "android/$module/src/main: missing (the gate would pass vacuously)"
  [ ! -d "$main" ] || [ "${scanned[$module]:-0}" -gt 0 ] || fail "android/$module/src/main: no sources found (the gate would pass vacuously)"
done

finish messaging-no-network
