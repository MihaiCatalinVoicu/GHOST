# ADR-16 — Rezistență la cenzură: bridges implicite, WebTunnel/obfs4/Snowflake, mod auto

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/LIMITE_REZIDUALE_SI_MITIGARI.md` §L4 |
| Faze | 6 (network), 12; P1 |

## Decizie propusă
Set de bridges livrat în manifestul semnat și rotit; mod auto (Tor direct → bridges, niciodată clearnet); opțiune explicită „ascunde utilizarea Tor” cu WebTunnel; opțiune Tor peste VPN documentată ca mutare de încredere. Test: captura de trafic nu conține fingerprint Tor cunoscut.
