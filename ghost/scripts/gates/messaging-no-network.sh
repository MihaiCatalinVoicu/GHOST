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
#   - `kotlinx.coroutines` (ADR-20: no coroutines in GHOST code; the DM actor is one thread, §13.7).
#
# Production sources are every Kotlin and Java file of the two modules' non-test source sets:
# `src/main`, and `src/gate`, `src/debug`, `src/release` where they exist (the `gate` build type is
# installed on the gate devices, §21.13 point 7). `src/test`, `src/androidTest`, `src/deviceRunner`
# and `src/equivalence` are test code and are not read.
#
# Like `dm-no-fts.sh` and `kotlin-clearnet.sh`, the scan is textual and a **comment** that names a
# banned package or class fails too, on purpose: a gate that had to tell prose from code would be a
# Kotlin parser with a parser's blind spots. Say it in the design document or in a test instead.
# What a text gate cannot see is a type alias declared in another module; that is the reviewer's,
# and the reason `:messaging` has no dependency on `:network` of its own (§13.1).
#
# Vacuity: both modules' `src/main` must exist and hold at least one source, or the gate fails
# rather than pass over a moved module.
#
# Usage: messaging-no-network.sh        (scans GHOST_ROOT, default: the ghost/ monorepo)
# Self-test: scripts/gates/self-test.sh points GHOST_ROOT at test-harness/gates/negative-dm-network-*.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

PACKAGES='\borg\.ghost\.network\b|\bjava\.net\b|\bjavax\.net\b|\bandroid\.net\b|\bandroid\.webkit\b|\bkotlinx\.coroutines\b|\bokhttp3\b|\bio\.ktor\b|\bretrofit2\b|\bcom\.android\.volley\b|\borg\.apache\.http\b'
CLASSES='\b(Socket|ServerSocket|DatagramSocket|MulticastSocket|SocketChannel|ServerSocketChannel|DatagramChannel|AsynchronousSocketChannel|AsynchronousServerSocketChannel|LocalSocket|LocalServerSocket|SSLSocket|SSLSocketFactory|SocketFactory|URL|URLConnection|HttpURLConnection|HttpsURLConnection|HttpClient|OkHttpClient|InetAddress|Inet4Address|Inet6Address|InetSocketAddress|WebView)\b'

for module in messaging crypto-bridge; do
  main="$GHOST_ROOT/android/$module/src/main"
  scanned=0
  for set in main gate debug release; do
    dir="$GHOST_ROOT/android/$module/src/$set"
    [ -d "$dir" ] || continue
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      [ "$set" = main ] && scanned=$((scanned + 1))
      rel="${f#"$GHOST_ROOT"/}"
      hits="$(grep -nP -- "$PACKAGES" "$f" || true)"
      [ -z "$hits" ] || while IFS= read -r line; do
        fail "$rel:$line (G-DM1: a DM module names a network package; the only way to a relay is the :sync API)"
      done <<< "$hits"
      hits="$(grep -nP -- "$CLASSES" "$f" || true)"
      [ -z "$hits" ] || while IFS= read -r line; do
        fail "$rel:$line (G-DM1: a DM module names a socket, address or HTTP class)"
      done <<< "$hits"
    done < <(find "$dir" -type f \( -name '*.kt' -o -name '*.java' \) 2>/dev/null | sort)
  done
  [ -d "$main" ] || fail "android/$module/src/main: missing (the gate would pass vacuously)"
  [ ! -d "$main" ] || [ "$scanned" -gt 0 ] || fail "android/$module/src/main: no sources found (the gate would pass vacuously)"
done

finish messaging-no-network
