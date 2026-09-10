# ADR-13 — Guvernanță în canal: flag-uri, prag, carantină, strike pe sponsor

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/LIMITE_REZIDUALE_SI_MITIGARI.md` §3.1 |
| Faze | 10 (primitive MLS), 13 (UX); P1 |

## Decizie propusă
Politica canalului ca obiect MLS semnat (prag = max(N, fracție), ponderare după vechime, diversitate a sponsorilor). Flag = mesaj MLS semnat; la prag: carantină (read-only, drept la răspuns) apoi Remove și epoch nou. Sponsorul unui membru scos primește strike; la K strike-uri pierde dreptul de Add. Liste de excludere semnate, opt-in; canale cu verificare a identității de bază pentru portabilitate. Nu există invalidare de APK: remediul este criptografic (Remove) și economic (strike).
