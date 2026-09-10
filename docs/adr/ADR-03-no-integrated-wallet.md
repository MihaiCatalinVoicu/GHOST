# ADR-03 — Fără portofel integrat în P0

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-09-10 (proprietar proiect) |
| Sursă | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §3 |
| Înlocuiește | Spec v2.0 FR-7.6, modul wallet |

## Decizie
Nu există portofel în aplicație în P0. Ramura `wallet` din ierarhia de chei rămâne rezervată (etichetă de domeniu definită, nefolosită), pentru a evita migrarea seed-ului dacă apare un rail on-chain opțional. Modulul `wallet` iese din Appendix B pentru P0; FR-7.6 devine inaplicabil.

## Consecințe
(+) fără chei financiare pe endpoint-ul de mesagerie; suprafață de audit mai mică. (−) plata se face din wallet extern (URI `monero:` / QR).
