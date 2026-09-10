# ADR-01 — Transport anonim: Tor (Arti) și relay-uri ca onion services

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §3 |
| Înlocuiește | Spec v2.0 FR-2.7, FR-5.6 (onion routing propriu), Faza 10 |

## Context
Onion routing propriu peste 3–5 relay-uri ale operatorului oferă un set de anonimat minuscul; primul hop vede IP-ul clientului; este un protocol de anonimat custom (contrar spiritului CP-09).

## Decizie
- Clientul Android încorporează Arti (Tor în Rust, prin JNI/UniFFI). Fallback acceptat: tor-android.
- Toate conexiunile (relay-uri, issuer, manifest de update) merg exclusiv prin Tor către adrese .onion v3 din manifestul semnat.
- Fără Tor: eșuare închisă — zero clearnet, zero DNS (test T6).
- Relay-urile acceptă trafic doar ca onion service; nu văd IP-uri structural.
- Gossip relay↔relay pe Noise (sau echivalent revizuit).
- Strat propriu de autentificare a cererilor (capabilități) independent de Tor.
- Padding pe bucket-uri înainte de trimiterea în Tor; circuit izolat per canal/scop.
- Bridges (obfs4/snowflake): P1.

## Consecințe
(+) set de anonimat = rețeaua Tor; fără DNS/IP expuse; fără protocol custom de auditat.
(−) latență (NFR-1 DM p95 < 5 s, NFR-2 post sync p95 < 8 s, măsurate); APK +5–10 MiB (NFR-4 < 80 MiB); dependență de Tor, atenuată prin bridges.
