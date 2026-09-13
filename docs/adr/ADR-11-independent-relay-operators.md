# ADR-11 — Relay-uri: independență reală a operatorilor

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §3 |
| Înlocuiește | Spec v2.0 §3 Operator (SHOULD), FR-5.6 |

## Decizie
Minimum 3 operatori independenți (entități și infrastructuri diferite) este MUST pentru producție. Inbound doar onion; disc criptat; fără access logs; nullifier set în memorie cu TTL; stocare redb (ADR-18) cu TTL de cel mult 90 zile; cote pe capabilitate. Clientul scrie fiecare blob pe ≥ 2 relay-uri.

## Corecturi de documentație (2026-09-13, design Faza 8 §18 F1)
- **Stocarea.** Textul aprobat spunea „RocksDB TTL 90 zile”. ADR-18 (aprobat 2026-09-10) a mutat stocarea relay-ului pe redb; decizia de aici nu se schimbă, iar TTL-ul maxim de 90 de zile rămâne (`ttl_bucket_days` ∈ {1, 7, 30, 90}). Corectură factuală, nu o decizie nouă.
- **Nullifier-ele.** „Nullifier set în memorie cu TTL” e textul aprobat. ADR-25 (propus 2026-09-12, aplicat în Faza 8) îl modifică: relay-ul persistă nullifier-ele în `nullifiers.redb`, cu etichetă de legare, cel mult două săptămâni (abaterea X1). Până la decizia proprietarului asupra ADR-25, această propoziție rămâne textul aprobat, iar codul Fazei 8 aplică ADR-25.
- **Staging.** Cele trei relay-uri de staging ale Fazei 8 sunt rulate de o singură parte; id-urile lor de operator sunt etichete, iar independența cerută aici nu se pretinde pentru staging (ADR-25 punctul 11).
