# ADR-09 — Metadate de trafic ca P0

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §3 |
| Înlocuiește | Spec v2.0 FR-2.5 (P1), FR-2.6 |

## Decizie
Padding pe bucket-uri 1/4/16/64 KiB devine P0. Jitter randomizat la sync; fetch în loturi de dimensiune fixă; circuit Tor izolat per canal/scop. Harness „relay capture” din Faza 5: un relay în mod test înregistrează tot ce poate vedea; testul (T1) eșuează la orice IP, identitate, plaintext sau dimensiune nepadată. Dummy traffic rămâne P2.
