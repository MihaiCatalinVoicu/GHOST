# ADR-07 — Open-source, build reproductibil, distribuție verificabilă

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §3 |
| Înlocuiește | Spec v2.0 §12.2 (HTTPS/IPFS), FR-8.1 |

## Decizie
Client, relay și issuer sunt open-source (licență: de stabilit înainte de prima publicare; opțiuni uzuale AGPL pentru server/issuer, MIT sau GPL pentru client). CI produce APK reproductibil: două medii independente trebuie să obțină același hash înainte de semnare (gate T12). Distribuție: manifest semnat + APK prin onion mirror; repo F-Droid propriu și/sau Accrescent. IPFS eliminat ca sursă primară. Anti-rollback și verificarea semnăturii rămân obligatorii (FR-7.5).
