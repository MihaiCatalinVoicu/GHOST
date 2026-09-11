# ADR-16 — Rezistență la cenzură: bridges implicite, WebTunnel/obfs4/Snowflake, mod auto

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/LIMITE_REZIDUALE_SI_MITIGARI.md` §L4 |
| Faze | 6 (network), 12; P1 |

## Decizie propusă
Set de bridges livrat în manifestul semnat și rotit; mod auto (Tor direct → bridges, niciodată clearnet); opțiune explicită „ascunde utilizarea Tor” cu WebTunnel; opțiune Tor peste VPN documentată ca mutare de încredere. Test: captura de trafic nu conține fingerprint Tor cunoscut.

## Stare la 2026-09-11 (după Faza 6)
Sunt suportate doar bridge-urile **simple** (`IP:PORT FINGERPRINT`), care au handshake Tor-TLS amprentabil. Liniile `obfs4`/`webtunnel`/`snowflake` sunt refuzate explicit cu categoria `bridge_config` (test unitar), astfel încât activarea transporturilor pluggable să fie o schimbare deliberată. Planul pentru Faza 12: feature `pt-client`, binarele lyrebird (obfs4 + webtunnel) și snowflake-client livrate ca `lib*.so` în `jniLibs`, teste de parsare și build pentru linii reale. Modul auto este posibil din Faza 6: crearea clientului e separată de bootstrap, iar bootstrap-ul are termen limită și poate fi anulat.
