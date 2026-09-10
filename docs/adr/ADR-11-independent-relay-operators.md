# ADR-11 — Relay-uri: independență reală a operatorilor

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §3 |
| Înlocuiește | Spec v2.0 §3 Operator (SHOULD), FR-5.6 |

## Decizie
Minimum 3 operatori independenți (entități și infrastructuri diferite) este MUST pentru producție. Inbound doar onion; disc criptat; fără access logs; nullifier set în memorie cu TTL; RocksDB TTL 90 zile; cote pe capabilitate. Clientul scrie fiecare blob pe ≥ 2 relay-uri.
