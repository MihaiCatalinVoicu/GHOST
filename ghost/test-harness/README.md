# test-harness/

Evidența executabilă a afirmațiilor de confidențialitate (CP-10). Nimic de aici nu este livrat utilizatorilor.

| Director | Conținut | Stare |
|---|---|---|
| `gates/negative/` | Fixture-uri intenționat greșite pentru gate-urile statice (`scripts/gates/self-test.sh`) | activ din Faza 1 |
| `privacy/` | Invarianții T1–T18 din threat model §9: schema observabilelor permise pentru relay, validatorul `capture-check`, fixture-uri pozitive/negative | activ din Faza 2 (T1 executabil); restul primesc implementări în fazele în care apar componentele |

Definițiile invarianților: [`privacy/INVARIANTS.md`](privacy/INVARIANTS.md).
