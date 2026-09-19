# ADR-07 — Open-source, build reproductibil, distribuție verificabilă

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect); **revizuit parțial de ADR-37 și ADR-38** (2026-09-16: sursă închisă; T12, manifestul semnat, mirror-ul onion și anti-rollback rămân) |
| Sursă | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §3 |
| Înlocuiește | Spec v2.0 §12.2 (HTTPS/IPFS), FR-8.1 |

## Decizie
Client, relay și issuer sunt open-source (licență: de stabilit înainte de prima publicare; opțiuni uzuale AGPL pentru server/issuer, MIT sau GPL pentru client). CI produce APK reproductibil: două medii independente trebuie să obțină același hash înainte de semnare (gate T12). Distribuție: manifest semnat + APK prin onion mirror; repo F-Droid propriu și/sau Accrescent. IPFS eliminat ca sursă primară. Anti-rollback și verificarea semnăturii rămân obligatorii (FR-7.5).

## Revizuire (2026-09-16)
Proprietarul a decis distribuția cu sursă închisă pentru client, relay și issuer. Clauza „Client, relay și issuer sunt open-source” și ținta „repo F-Droid” (în sensul depozitului principal F-Droid) sunt înlocuite de [ADR-37](ADR-37-closed-source-licences.md) (licență proprietară, conformitatea licențelor terților); verificabilitatea fără sursă publică este [ADR-38](ADR-38-verifiability-without-source.md) (audituri publicate, build reprodus de auditor, jurnal de transparență binară). Build-ul reproductibil (T12), manifestul semnat, mirror-ul onion și anti-rollback rămân în vigoare. Ambele ADR sunt propuse și aplicate în Faza 9 (Q4).
