# ADR-15 — Traffic shaping: polling constant, trimitere întârziată, bucketizare la citire

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/LIMITE_REZIDUALE_SI_MITIGARI.md` §L2 |
| Faze | 7 (sync), 12 (hardening); P1, bucketizare P2 |

## Decizie propusă
Polling la interval fix + jitter cu loturi de dimensiune fixă, independent de activitate. Trimitere întârziată aleatoriu 0–N minute, implicit în high-privacy mode. Bucketizare a canalelor la fetch (PIR-lite). Test de acceptare: distribuția traficului idle vs activ statistic indistinctă; cost măsurat în NFR-5.
