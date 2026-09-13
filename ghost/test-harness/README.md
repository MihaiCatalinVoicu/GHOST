# test-harness/

Evidența executabilă a afirmațiilor de confidențialitate (CP-10). Nimic de aici nu este livrat utilizatorilor.

| Director | Conținut | Stare |
|---|---|---|
| `gates/negative*/` | Fixture-uri intenționat greșite pentru gate-urile statice (`scripts/gates/self-test.sh`): `negative/`, `negative-client-core/`, `negative-sync/` (`sync-no-catch-all.sh`), `negative-clearnet/` (`kotlin-clearnet.sh`), `negative-merged-manifest/` (`merged-manifest-lint.sh`, cu un fixture pozitiv în `positive/`) | activ din Faza 1; extins în Fazele 6 și 7 |
| `privacy/` | Invarianții T1–T21 din threat model §9: schema observabilelor permise pentru relay, validatorul `capture-check`, fixture-uri pozitive/negative | activ din Faza 2 (T1 executabil); restul primesc implementări în fazele în care apar componentele |
| `privacy/t2-join/` | Analizorul T2 (`ghost-t2-join`, design Faza 8 §13.4): căutarea de join J1–J10, T2b, T2c și testele statistice S1–S4 peste vederile complete ale issuer-ului și relay-urilor din lumea T2 (`issuer/crates/service/tests/t2/`, `t2_unlinkability.rs`, `t2_mutants.rs`) | activ din Faza 8 (S10) |
| `gates/t2-report/` | Rapoarte fixture pentru `scripts/gates/t2-report-check.sh` (raport complet de gate și de PR, raport cu o verificare lipsă sau picată, scară greșită, o verificare trecută pe un eșantion gol, 23 respectiv 22 de mutanți detectați) | activ din Faza 8 (S10) |

Definițiile invarianților: [`privacy/INVARIANTS.md`](privacy/INVARIANTS.md).
