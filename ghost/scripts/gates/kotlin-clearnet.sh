#!/usr/bin/env bash
# Gate T6, Kotlin side (Phase 7 design §5.5, ADR-19): the Android client reaches the network only
# through the embedded Tor core (org.ghost.network.TorRelayTransport, then JNI into client-core).
# No production source under android/*/src/main (Kotlin or Java) may use a JVM clearnet primitive:
#   - java.net sockets (Socket, ServerSocket, DatagramSocket, MulticastSocket, SocketImpl), URLs and
#     URL connections (URL, URLConnection, HttpURLConnection, JarURLConnection), name resolution and
#     addresses (InetAddress, Inet4Address, Inet6Address, InetSocketAddress), proxies (Proxy,
#     ProxySelector), the java.net.http client, or a java.net wildcard import;
#   - java.net.URI turned into a URL (toURL()) in a file that uses java.net.URI;
#   - anything in javax.net (socket factories, TLS).
# The Rust side is covered by the clippy clearnet bans (clippy-clearnet-fixture.sh).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
BANNED='\bjava\.net\.(\*|(Socket|SocketImpl|ServerSocket|DatagramSocket|MulticastSocket|URL|URLConnection|HttpURLConnection|JarURLConnection|InetAddress|Inet4Address|Inet6Address|InetSocketAddress|Proxy|ProxySelector|http)\b)|\bjavax\.net\b'
checked=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  checked=$((checked + 1))
  hits="$(grep -nP -- "$BANNED" "$f" || true)"
  [ -z "$hits" ] || while IFS= read -r line; do fail "$f:$line (clearnet primitive; the only network path is the Tor core)"; done <<< "$hits"
  if grep -qP '\bjava\.net\.URI\b' "$f"; then
    hits="$(grep -nP -- '\.toURL\s*\(' "$f" || true)"
    [ -z "$hits" ] || while IFS= read -r line; do fail "$f:$line (java.net.URI.toURL opens a clearnet URL)"; done <<< "$hits"
  fi
done < <(android_main_files)
[ "$checked" -gt 0 ] || fail "$GHOST_ROOT/android: no src/main sources found (the gate would pass vacuously)"
finish kotlin-clearnet
